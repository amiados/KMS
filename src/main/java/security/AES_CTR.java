package security;

import java.security.SecureRandom;
import java.util.Arrays;
import static security.AES_ECB.*;

public class AES_CTR {

    private static final int IV_LENGTH = 12; // אורך ה-IV (12 בתים, 96 ביטים)
    private static final int BLOCK_SIZE = 16; // גודל הבלוק ב-AES (16 בתים)

    /**
     * Decrypt a plaintext of arbitrary length (same as encrypt)
     *
     * @param ciphertext the data to encrypt
     * @param roundKeys based on the 16-byte AES key
     * @param iv a 12-byte nonce; we’ll append a 4-byte counter to make 16 bytes total
     * @return ciphertext (same length as plaintext)
     */
    protected static byte[] decryptCTR(byte[] ciphertext, byte[][] roundKeys, byte[] iv) {
        return encryptCTR(ciphertext, roundKeys, iv);  // הפענוח הוא זהה להצפנה במצב security.AES_CTR
    }

    /**
     * Encrypt a plaintext of arbitrary length.
     *
     * @param plainText the data to encrypt
     * @param roundKeys based on the 16-byte AES key
     * @param ivOrCounter a 12-byte nonce; we’ll append a 4-byte counter to make 16 bytes total
     * @return ciphertext (same length as plaintext)
     */
    protected static byte[] encryptCTR(byte[] plainText, byte[][] roundKeys, byte[] ivOrCounter) {
        byte[] counter;
        if (ivOrCounter.length == IV_LENGTH) {
            // IV בן 12, נעביר ל־16 בתים עם padding של אפסים
            counter = Arrays.copyOf(ivOrCounter, BLOCK_SIZE);
        } else if (ivOrCounter.length == BLOCK_SIZE) {
            // כבר מונה מלא של 16 בתים
            counter = ivOrCounter.clone();
        } else {
            throw new IllegalArgumentException("Expected 12-byte IV or 16-byte counter, got "
                    + ivOrCounter.length);
        }

        byte[] cipher = new byte[plainText.length];
        byte[] encryptedCounter; // משתנה לשמירת התוצאה לאחר הצפנת האוגדן

        // הצפנה של ההודעה בלוקים, כאשר כל בלוק בגודל BLOCK_SIZE
        for (int pos = 0; pos < plainText.length; pos += BLOCK_SIZE) {

            // הצפנת האוגדן הנוכחי
            encryptedCounter = encrypt_block(counter, roundKeys);

            // חישוב ה-XOR בין האוגדן המוצפן להודעה הגולמית כדי לקבל את ההודעה המפוצפת
            int blockLength = Math.min(BLOCK_SIZE, plainText.length - pos);
            xor(encryptedCounter, plainText, pos, blockLength, cipher, pos);

            // הגדלת האוגדן לצורך השימוש הבא
            incrementCounter(counter);
        }
        return cipher;
    }

    // פונקציה לחישוב XOR בין אוגדן מוצפן להודעה, ותוצאה שתישמר במערך המוצפן
    private static void xor(byte[] encryptedCounter, byte[] plainText, int pos, int length, byte[] cipher, int outPos) {
        for (int i = 0; i < length; i++)
            cipher[outPos + i] = (byte) (plainText[pos + i] ^ encryptedCounter[i]);
    }

    // פונקציה ליצירת IV ייחודי בעזרת SecureRandom
    public static byte[] ivGenerator() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    // פונקציה להגדלת אוגדן הספירה ב-1
    // זהו תהליך של חיבור מחזורי, המתחיל מהבית הפחות משמעותי (LSB) וממשיך עד להגעת הבית המשמעותי ביותר (MSB)
    private static void incrementCounter(byte[] counter) {

        for (int i = BLOCK_SIZE - 1; i >= IV_LENGTH; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                break;
            }
        }

    }

}
