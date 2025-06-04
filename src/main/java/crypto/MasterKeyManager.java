package crypto;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static security.AES_ECB.keySchedule;
import static security.AES_GCM.*;

public class MasterKeyManager {
    // שם הקובץ שבו נשמר ה-master key המוצפן
    private static final Path MASTER_KEY_FILE = Paths.get("src/resources/master_key.enc");

    // פרמטרים ל-AES-GCM
    private static final int AES_KEY_SIZE = 16;       // 16 bytes = 128 bits
    private static final int IV_LENGTH = 12;      // 12 bytes = 96 bits
    private static final byte[] AAD = "MyGlobalAAD".getBytes(StandardCharsets.UTF_8);

    private final byte[] rawMasterKey; // יאוחסן בזיכרון אחרי טעינה/יצירה


    /**
     * בונה את ה-MasterKeyManager:
     * - passphraseBytes: raw bytes של הסיסמה (למשל, "myPass".getBytes(StandardCharsets.UTF_8))
     * - אם כבר קיימת קובץ master_key.enc → טוען, מפענח באמצעות AES-GCM ומחזיר rawMasterKey.
     * - אחרת → יוצר rawMasterKey אקראי, מצפין ב-AES-GCM ושומר לקובץ.
     *
     * @param passphraseBytes raw bytes של הסיסמה
     * @throws Exception בטעויות IO או הצפנה/פענוח
     */
    public MasterKeyManager(byte[] passphraseBytes) throws Exception {
        byte[] aesKey = deriveAesKey(passphraseBytes);

        if (Files.exists(MASTER_KEY_FILE)) {
            // load existing master key
            this.rawMasterKey = loadMasterKey(aesKey);
            System.out.println("[MasterKeyManager] Loaded existing Master Key (AES-128).");
        } else {
            // generate new master key and store it encrypted
            this.rawMasterKey = generateAndStoreMasterKey(aesKey);
            System.out.println("[MasterKeyManager] Generated and stored new Master Key (AES-128).");
        }
        Arrays.fill(passphraseBytes, (byte) 0);
    }

    /**
     * מפענח את master_key.enc:
     * - קורא את כל הנתונים (IV || ciphertext || tag),
     * - יוצר roundKeys בעזרת aesKey (byte[16]) + keySchedule,
     * - מפעיל AES_GCM.decrypt על כל המערך,
     * - מחזיר rawMasterKey (16 בתים).
     *
     * @param aesKey 16 בתים (AES-128) שגזור מתוך הסיסמה
     * @return rawMasterKey (16 בתים)
     * @throws Exception בטעויות IO או פענוח
     */
    private byte[] loadMasterKey(byte[] aesKey) throws Exception {
        // 1. קרא את הקובץ המלא
        byte[] fileData = Files.readAllBytes(MASTER_KEY_FILE);

        if (fileData == null || fileData.length == 0) {
            throw new IllegalStateException("אין נתונים להצפנה/פענוח: הקובץ ריק או לא נמצא");
        }
        // 2. נבנה roundKeys מתוך aesKey
        byte[][] roundKeys = new byte[11][AES_KEY_SIZE];
        System.arraycopy(aesKey, 0, roundKeys[0], 0, AES_KEY_SIZE);
        keySchedule(roundKeys);

        // 3. מפעילים AES-GCM.decrypt:
        //    מימוש AES_GCM שלנו מצפה לקבל מערך שבו ההתחלה היא IV (12 בתים)
        //    והחלק שנותר הוא ciphertext||tag
        byte[] rawMaster = decrypt(fileData, AAD, roundKeys);

        // 4. מנקים את fileData מהזיכרון (מטח כדי שלא ישאר ישן)
        Arrays.fill(fileData, (byte) 0);

        return rawMaster;
    }

    /**
     * גוזר מפתח AES-128 מתוך הסיסמה:
     * מחשב SHA-256(passphraseBytes) ולוקח את ה-16 בתים הראשונים.
     *
     * @param passphraseBytes raw bytes של הסיסמה
     * @return byte[16] – AES-128 key
     * @throws Exception בטעויות של MessageDigest.getInstance
     */
    private byte[] deriveAesKey(byte[] passphraseBytes) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest(passphraseBytes);
        return Arrays.copyOf(digest, AES_KEY_SIZE);
    }

    /**
     * יוצר rawMasterKey אקראי (16 בתים), מצפין אותו ב־AES-GCM תחת aesKey, ושומר לקובץ master_key.enc:
     * - הצפנה: AES_GCM.encrypt(plaintext=rawMaster, AAD=null, roundKeys)
     * - הפלט: IV (12 בתים) || ciphertext || tag => כל אלה נשמרים תחת master_key.enc
     *
     * @param aesKey 16 בתים (AES-128) שגזור מתוך הסיסמה
     * @return rawMasterKey (16 בתים)
     * @throws Exception בטעויות IO או הצפנה
     */
    private byte[] generateAndStoreMasterKey(byte[] aesKey) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();

        // א) נייצר rawRandomMaster (16 בתים)
        byte[] rawMaster = new byte[AES_KEY_SIZE];
        random.nextBytes(rawMaster);

        // ב) נבנה roundKeys להפעלת AES-GCM
        byte[][] roundKeys = new byte[11][AES_KEY_SIZE];
        System.arraycopy(aesKey, 0, roundKeys[0], 0, AES_KEY_SIZE);
        keySchedule(roundKeys);

        // ג) ניצור IV אקראי (12 בתים)
        byte[] iv = ivGenerator();

        // ד) נפעיל את AES_GCM.encrypt(plaintext=rawMaster, AAD=null, roundKeys)
        byte[] cipherPlusTag = encrypt(rawMaster, AAD, roundKeys);

        // ה) נחבר iv || cipherPlusTag
        byte[] fileData = new byte[IV_LENGTH + cipherPlusTag.length];
        System.arraycopy(iv, 0, fileData, 0, IV_LENGTH);
        System.arraycopy(cipherPlusTag, 0, fileData, IV_LENGTH, cipherPlusTag.length);

        // ו) נשמור ל־disk כ master_key.enc
        Files.createDirectories(MASTER_KEY_FILE.getParent());
        Files.write(MASTER_KEY_FILE, fileData);

        // ז) מאפסים את cipherPlusTag (כבר נשמר בדיסק)
        Arrays.fill(cipherPlusTag, (byte) 0);

        // ח) מחזירים עותק של rawMaster כדי לשמור בזיכרון
        return rawMaster.clone();
    }

    /**
     * מחזיר עותק של ה-rawMasterKey (16 בתים).
     * @return rawMasterKey clone
     */
    public byte[] getMasterKeyRaw() {
        return rawMasterKey.clone();
    }


}
