package crypto;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static security.AES_ECB.keySchedule;
import static security.AES_GCM.*;

/**
 * MasterKeyManager:
 * - יוצר/טוען master_key.enc בפורמט:
 *   [ MAGIC(16) | VERSION(1) | SALT(16) | (IV||CT||TAG) ]
 * - AAD = MAGIC || VERSION || SALT
 * - תמיכה במיגרציה מהפורמט הישן: [IV(12) || CT(16) || TAG(16)] עם AAD="GlobalAAD" וללא SALT.
 * - כל ההצפנה/פענוח משתמשת ב-AES-128 (roundKeys[11][16]).
 */
public class MasterKeyManager {

    // שם הקובץ שבו נשמר ה-master key המוצפן
    private static final Path MASTER_KEY_FILE = Paths.get("master_key.enc");
    // פרמטרים ל-AES-GCM ופורמט ישן/חדש
    private static final int AES_KEY_SIZE = 16;   // 16 bytes = 128-bit key
    private static final int IV_LENGTH    = 12;   // 12 bytes = 96-bit nonce
    private static final int TAG_LENGTH   = 16;   // 16 bytes GCM tag
    private static final int SALT_LENGTH  = 16;   // 16 bytes salt

    // כותרת/גרסה (פורמט חדש)
    private static final byte[] MAGIC   = padMagic("KMS-MASTER-KEY", 16); // בדיוק 16 בתים
    private static final byte   VERSION = 0x01;

    // המפתח הראשי הגולמי (AES-128 אצלך)
    private final byte[] rawMasterKey;

    /**
     * C'tor: אם הקובץ קיים – טוען; אחרת – יוצר ושומר בפורמט החדש.
     */
    public MasterKeyManager(byte[] passphraseBytes) throws Exception {
        if (Files.exists(MASTER_KEY_FILE)) {
            this.rawMasterKey = loadMasterKey(passphraseBytes);
            System.out.println("[MasterKeyManager] Loaded existing Master Key (AES-128).");
        } else {
            this.rawMasterKey = generateAndStoreMasterKey(passphraseBytes);
            System.out.println("[MasterKeyManager] Generated and stored new Master Key (AES-128).");
        }
        Arrays.fill(passphraseBytes, (byte)0);
    }

    /**
     * טעינת master_key.enc:
     * 1) ניסיון פורמט חדש (MAGIC+VERSION+SALT + blob=IV||CT||TAG)
     * 2) אם לא – מיגרציה מהפורמט הישן (IV||CT||TAG, AAD="GlobalAAD", ללא salt), ואז כתיבה מחדש בפורמט החדש.
     */
    private byte[] loadMasterKey(byte[] passphraseBytes) throws Exception {
        byte[] fileData = Files.readAllBytes(MASTER_KEY_FILE);

        // ----- ניסיון פורמט חדש -----
        if (fileData.length >= MAGIC.length + 1 + SALT_LENGTH + IV_LENGTH + TAG_LENGTH) {
            ByteBuffer buf = ByteBuffer.wrap(fileData);

            byte[] magic = new byte[16]; // 16 קבועים ל-MAGIC
            buf.get(magic);
            byte version = buf.get();

            if (Arrays.equals(magic, MAGIC) && version == VERSION) {
                byte[] salt = new byte[SALT_LENGTH];
                buf.get(salt);

                // blob = IV||CT||TAG (בפורמט AES_GCM שלך)
                byte[] blob = new byte[buf.remaining()];
                buf.get(blob);

                // נגזור KEK מ-pass||salt
                byte[] aesKey = deriveAesKey(passphraseBytes, salt);
                byte[][] roundKeys = new byte[11][AES_KEY_SIZE];
                System.arraycopy(aesKey, 0, roundKeys[0], 0, AES_KEY_SIZE);
                keySchedule(roundKeys);

                // AAD = MAGIC||VERSION||SALT
                byte[] aad = buildAAD(MAGIC, VERSION, salt);

                // פענוח (לתשומת לב: להשתמש ב-blob, לא ב-fileData)
                byte[] rawMaster = decrypt(blob, aad, roundKeys);

                Arrays.fill(fileData, (byte)0);
                Arrays.fill(aesKey,   (byte)0);
                return rawMaster;
            }
        }

        // ----- מיגרציה מפורמט ישן (אין MAGIC/Version/Salt) -----
        // הפורמט הישן אצלך: IV(12) || CT(16) || TAG(16) = 44 בתים
        if (fileData.length == (IV_LENGTH + AES_KEY_SIZE + TAG_LENGTH)) {
            try {
                // KEK ישן: SHA-256(pass)[0..15]
                byte[] legacyAesKey = deriveLegacyAesKey(passphraseBytes);
                byte[][] rk = new byte[11][AES_KEY_SIZE];
                System.arraycopy(legacyAesKey, 0, rk[0], 0, AES_KEY_SIZE);
                keySchedule(rk);

                byte[] legacyAAD = "GlobalAAD".getBytes(StandardCharsets.UTF_8);

                // כאן בפורמט הישן – decrypt מקבל ישירות את fileData (IV||CT||TAG)
                byte[] rawMaster = decrypt(fileData, legacyAAD, rk);

                // כתיבה מחדש בפורמט החדש
                rewriteInNewFormat(passphraseBytes, rawMaster);

                Arrays.fill(fileData,    (byte)0);
                Arrays.fill(legacyAesKey,(byte)0);
                return rawMaster;
            } catch (Exception ex) {
                Arrays.fill(fileData, (byte)0);
                throw new IllegalStateException("Invalid master_key.enc MAGIC/VERSION and legacy decode failed", ex);
            }
        }

        Arrays.fill(fileData, (byte)0);
        throw new IllegalStateException("Invalid master_key.enc MAGIC/VERSION");
    }

    /**
     * יצירת master_key.enc חדש בפורמט:
     * [ MAGIC | VERSION | SALT | (IV||CT||TAG) ]
     * כאשר AAD= MAGIC||VERSION||SALT, וה-rawMasterKey הוא 16 בתים (AES-128).
     */
    private byte[] generateAndStoreMasterKey(byte[] passphraseBytes) throws Exception {
        SecureRandom rng = SecureRandom.getInstanceStrong();

        // raw master (AES-128 אצלך = 16 בתים)
        byte[] rawMaster = new byte[AES_KEY_SIZE];
        rng.nextBytes(rawMaster);

        // salt אקראי לגזירת ה-KEK
        byte[] salt = new byte[SALT_LENGTH];
        rng.nextBytes(salt);

        // נגזר KEK מ-pass||salt (128-bit)
        byte[] aesKey = deriveAesKey(passphraseBytes, salt);
        byte[][] roundKeys = new byte[11][AES_KEY_SIZE];
        System.arraycopy(aesKey, 0, roundKeys[0], 0, AES_KEY_SIZE);
        keySchedule(roundKeys);

        // AAD הצמוד לקובץ
        byte[] aad = buildAAD(MAGIC, VERSION, salt);

        // הצפנה בפורמט שלך: encrypt מחזיר blob = IV||CIPHERTEXT||TAG
        byte[] blob = encrypt(rawMaster, aad, roundKeys);

        // כתיבה לפורמט הקובץ
        ByteBuffer out = ByteBuffer.allocate(MAGIC.length + 1 + SALT_LENGTH + blob.length);
        out.put(MAGIC);
        out.put(VERSION);
        out.put(salt);
        out.put(blob);

        Path parent = MASTER_KEY_FILE.getParent();
        if (parent != null && Files.notExists(parent)) {
            Files.createDirectories(parent);
        }
        Files.write(MASTER_KEY_FILE, out.array());

        Arrays.fill(aesKey, (byte)0);
        Arrays.fill(blob,   (byte)0);

        return rawMaster.clone();
    }

    /** גזירת מפתח AES-128 מ-(pass||salt) באמצעות SHA-256 ואז חיתוך ל-16 בתים. */
    private byte[] deriveAesKey(byte[] passphraseBytes, byte[] salt) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(passphraseBytes);
        sha256.update(salt);
        byte[] digest = sha256.digest();
        return Arrays.copyOf(digest, AES_KEY_SIZE); // 16 בתים (AES-128)
    }

    /** גזירת KEK לפורמט הישן: SHA-256(pass)[0..15] ללא salt. */
    private byte[] deriveLegacyAesKey(byte[] passphraseBytes) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(passphraseBytes);
        return Arrays.copyOf(digest, AES_KEY_SIZE);
    }

    /** כתיבה מחדש בפורמט החדש, לאחר שהצלחנו לפענח את ה-master מהפורמט הישן. */
    private void rewriteInNewFormat(byte[] passphraseBytes, byte[] rawMaster) throws Exception {
        SecureRandom rng = SecureRandom.getInstanceStrong();

        byte[] salt = new byte[SALT_LENGTH];
        rng.nextBytes(salt);

        byte[] aesKey = deriveAesKey(passphraseBytes, salt);
        byte[][] roundKeys = new byte[11][AES_KEY_SIZE];
        System.arraycopy(aesKey, 0, roundKeys[0], 0, AES_KEY_SIZE);
        keySchedule(roundKeys);

        byte[] aad  = buildAAD(MAGIC, VERSION, salt);
        byte[] blob = encrypt(rawMaster, aad, roundKeys); // IV||CT||TAG

        ByteBuffer out = ByteBuffer.allocate(MAGIC.length + 1 + SALT_LENGTH + blob.length);
        out.put(MAGIC);
        out.put(VERSION);
        out.put(salt);
        out.put(blob);

        Path parent = MASTER_KEY_FILE.getParent();
        if (parent != null && Files.notExists(parent)) {
            Files.createDirectories(parent);
        }
        Files.write(MASTER_KEY_FILE, out.array());

        Arrays.fill(aesKey, (byte)0);
        Arrays.fill(blob,   (byte)0);
    }

    /** בניית AAD = MAGIC || VERSION || SALT */
    private static byte[] buildAAD(byte[] magic, byte version, byte[] salt) {
        byte[] aad = new byte[magic.length + 1 + salt.length];
        System.arraycopy(magic, 0, aad, 0, magic.length);
        aad[magic.length] = version;
        System.arraycopy(salt, 0, aad, magic.length + 1, salt.length);
        return aad;
    }

    /** ריפוד ASCII ל-16 בתים בדיוק עבור MAGIC */
    private static byte[] padMagic(String s, int len) {
        byte[] b = new byte[len];
        byte[] raw = s.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(raw, 0, b, 0, Math.min(raw.length, len));
        return b;
    }

    /** מקבל עותק של ה-master key (16 בתים). נקה לאחר שימוש. */
    public byte[] getMasterKeyRaw() {
        return rawMasterKey.clone();
    }
}
