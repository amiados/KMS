package security;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AES_ECB מממש את אלגוריתם AES במצב ECB (Electronic Codebook).
 * כולל את שלבי ההצפנה והפענוח: SubBytes, ShiftRows, MixColumns, AddRoundKey וכן Key Schedule.
 */
public class AES_ECB {

    /** גודל בלוק AES בבתים */
    private static final int BLOCK_SIZE = 16;

    /** טבלת תחליף (S-Box) לשלב ה-SubBytes */
    private static final byte[] sodBox = new byte[] {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
            (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
            (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
            (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
            (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
            (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
            (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
            (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
            (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
            (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
            (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
            (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
            (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16 };

    /** טבלת התחליף ההפוכה (Inverse S-Box) לשלב ה-InverseSubBytes */
    private static final byte[] inverseSodBox = new byte[] {
            (byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb,
            (byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb,
            (byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e,
            (byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25,
            (byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92,
            (byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
            (byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06,
            (byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b,
            (byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73,
            (byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e,
            (byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b,
            (byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4,
            (byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f,
            (byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef,
            (byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
            (byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d };

    /**
     * מקבלת בלוק נתונים ומפתחי סיבובים ומחזירה מערך מוצפן בפורמט ECB:
     * - מוסיפה PKCS#7 padding
     * - מפצלת לבלוקים של 16 בתים
     * - מפעילה encrypt_block על כל בלוק
     */
    private static byte[] encryption(byte[] message, byte[][] round_keys){

        // padding the message
        byte[] paddedMessage = addPadding(message, BLOCK_SIZE);
        System.out.println("padded: " + Arrays.toString(paddedMessage));

        // iterate on the padded Messages and encrypt each block separately and copy them back to the padded Messages
        for(int position=0; position<paddedMessage.length; position+=BLOCK_SIZE){
            byte[] block = Arrays.copyOfRange(paddedMessage, position, position+BLOCK_SIZE);
            byte[] encryptedBlock = encrypt_block(block, round_keys);
            System.arraycopy(encryptedBlock, 0, paddedMessage, position, BLOCK_SIZE);
        }
        return paddedMessage;
    }

    /**
     * פענוח של בלוק נתונים מוצפן.
     * @param cipherText בלוק נתונים מוצפן.
     * @param round_keys המפתח ששימש להצפנה.
     * @return בלוק נתונים מפוענח.
     */
    private static byte[] decryption(byte[] cipherText, byte[][] round_keys){

        for(int position=0; position < cipherText.length; position+=BLOCK_SIZE){

            // copy a block from the encrypted message
            byte[] block = Arrays.copyOfRange(cipherText, position, position+BLOCK_SIZE);

            // decrypt the selected block
            byte[] decryptedBlock = decrypt_block(block, round_keys);

            System.arraycopy(decryptedBlock, 0, cipherText, position, BLOCK_SIZE);
        }
        return removePadding(cipherText, BLOCK_SIZE);
    }

    /**
     * הצפנת בלוק יחיד (AES-128):
     * 1. AddRoundKey עם מפתח סיבוב 0
     * 2. 9 סיבובים של SubBytes, ShiftRows, MixColumns, AddRoundKey
     * 3. סיבוב אחרון של SubBytes, ShiftRows, AddRoundKey
     */
    protected static byte[] encrypt_block(byte[] input, byte[][] rounds_key){
        byte[] state = Arrays.copyOf(input, BLOCK_SIZE);

        addRoundKey(state, rounds_key[0]);
        for(int round=1; round<=9; round++){
            subByte(state);
            shiftRows(state);
            mixColumns(state);  // Mix columns only in the first 9 rounds
            addRoundKey(state, rounds_key[round]);
        }

        // Final round (round 10), no mixColumns
        subByte(state);
        shiftRows(state);
        addRoundKey(state, rounds_key[10]);
        return state;
    }

    /**
     * פענוח בלוק יחיד:
     * 1. AddRoundKey עם מפתח סיבוב 10
     * 2. 9 סיבובים של InverseShiftRows, InverseSubByte, AddRoundKey, InverseMixColumns
     * 3. סיבוב אחרון של InverseShiftRows, InverseSubByte, AddRoundKey
     */
    private static byte[] decrypt_block(byte[] input, byte[][] round_keys) {
        byte[] state = Arrays.copyOf(input, BLOCK_SIZE);

        addRoundKey(state, round_keys[10]);  // start with the last round key
        for (int round = 9; round >= 1; round--) {
            inverseShiftRows(state);
            inverseSubByte(state);
            addRoundKey(state, round_keys[round]);
            inverseMixColumns(state);  // Inverse of mixColumns for each round except the last
        }
        inverseShiftRows(state);
        inverseSubByte(state);
        addRoundKey(state, round_keys[0]);  // final addRoundKey without mixColumns
        return state;
    }

    // taking the "old key" and creating with it a new key (making the decryption process much harder)
    // don't want the function to be void because I need the original row in Rcon
    // can save another byte[] for this thing

    /**
     * מפתח סיבובי (Key Schedule) ל-AES-128:
     * יוצר 11 מפתחות של 16 בתים כל אחד
     */
    public static void keySchedule(byte[][] cipherKeys) {
        // 10 ROUNDS OF KEY SCHEDULE
        for(int round = 1; round < 11; round++){
            byte[] temp = Arrays.copyOfRange(cipherKeys[round-1], BLOCK_SIZE - 4, BLOCK_SIZE);

            // RotWord: Rotate the first column
            rotWord(temp, 1);

            // SubByte: Apply substitution using the S-box
            subByte(temp);

            // XOR with Rcon (only on the first byte of the column)
            temp[0] ^= Rcon(round);

            // OTHER ROWS:
            // w(i) = w(i-1) ^ w(i-4)
            for(int byteCell = 0; byteCell < BLOCK_SIZE; byteCell++) {
                cipherKeys[round][byteCell] = (byte) (cipherKeys[round - 1][byteCell] ^ temp[byteCell % 4]);
                // Update temp only for the first 4 bytes
                if (byteCell < 4) {
                    temp[byteCell] = cipherKeys[round][byteCell];
                }
            }
        }

    }

    /**
     * Rotate-Word: מזיז את המילה (4 בתים) ב-x מיקומים שמאלה
     */
    private static void rotWord(byte[] word, int times) {
        for(int i=0; i<times; i++){
            byte temp = word[0];
            System.arraycopy(word, 1, word, 0, word.length - 1);
            word[word.length - 1] = temp;
        }
    }

    private static void inverse_rotWord(byte[] word, int times) {
        for (int i = 0; i < times; i++) {
            byte temp = word[word.length - 1];
            System.arraycopy(word, 0, word, 1, word.length - 1);
            word[0] = temp;
        }
    }

    /**
     * מחולל מפתח אקראי ראשוני (16 בתים) עבור AES
     */
    public static byte[] keyGenerator() {
        // use the 'SecureRandom' package to generate a more random value
        // (by using Random system sources that are not easily predictable such as timing of laboratory operations, hardware noise, etc.)
        // creating a byte array and filling it with random bytes
        SecureRandom random = new SecureRandom();
        byte[] keyBlock = new byte[BLOCK_SIZE];
        random.nextBytes(keyBlock);
        return keyBlock;
    }

    // third operation:
    // need to go over again to make sure I understand how and why this happens

    /**
     * mixColumns: שילוב עמודות בשדה GF(2^8) לפי תקן AES
     */
    private static void mixColumns(byte[] state) {
        // processes each column of the state matrix by performing a series of byte multiplications and XOR operations.

        for(int col=0; col<4; col++){
            byte[] column = new byte[4];

            // Extract the current column
            for(int i=0; i<4; i++)
                column[i] = state[i*4 + col];

            byte[] result = new byte[4];

            result[0] = (byte) (GMul((byte) 0x02, column[0]) ^ GMul((byte) 0x03, column[1]) ^ column[2] ^ column[3]);
            result[1] = (byte) (column[0] ^ GMul((byte) 0x02, column[1]) ^ GMul((byte) 0x03, column[2]) ^ column[3]);
            result[2] = (byte) (column[0] ^ column[1] ^ GMul((byte) 0x02, column[2]) ^ GMul((byte) 0x03, column[3]));
            result[3] = (byte) (GMul((byte) 0x03, column[0]) ^ column[1] ^ column[2] ^ GMul((byte) 0x02, column[3]));

            // write the result back to the state array
            for (int i = 0; i < 4; i++) {
                state[i * 4 + col] = result[i];
            }
        }
    }

    /**
     * InverseMixColumns: הפוך הפעולה של mixColumns
     */
    private static void inverseMixColumns(byte[] state) {
        for (int col = 0; col < 4; col++) {
            byte[] column = new byte[4];

            // Extract the current column
            for(int i=0; i<4; i++)
                column[i] = state[i*4 + col];

            // Apply the inverse mix columns transformation
            byte[] result = new byte[4];
            result[0] = (byte) (GMul(column[0], (byte) 0x0E) ^ GMul(column[3], (byte) 0x09) ^ GMul(column[2], (byte) 0x0D) ^ GMul(column[1], (byte) 0x0B));
            result[1] = (byte) (GMul(column[1], (byte) 0x0E) ^ GMul(column[0], (byte) 0x09) ^ GMul(column[3], (byte) 0x0D) ^ GMul(column[2], (byte) 0x0B));
            result[2] = (byte) (GMul(column[2], (byte) 0x0E) ^ GMul(column[1], (byte) 0x09) ^ GMul(column[0], (byte) 0x0D) ^ GMul(column[3], (byte) 0x0B));
            result[3] = (byte) (GMul(column[3], (byte) 0x0E) ^ GMul(column[2], (byte) 0x09) ^ GMul(column[1], (byte) 0x0D) ^ GMul(column[0], (byte) 0x0B));

            // write the result back to the state array
            for (int i = 0; i < 4; i++)
                state[i * 4 + col] = result[i];
        }
    }

    /**
     * Multiply שני בתים בשדה גאלואה GF(2^8) עם פולינום x^8 + x^4 + x^3 + x + 1
     */
    protected static byte GMul(byte multiplicand, byte multiplier) {
        byte result = 0, MSB; // to store result and MSB of the current multiplication
        for (int i = 0; i < 8; i++) {
            byte mask = (byte) (-(multiplier & 1)); // deals with bit shifts
            result ^= (byte) (multiplicand & mask); // XOR with the multiplicand

            MSB = (byte) (multiplicand & 0x80); // MSB check for modulo
            multiplicand <<= 1; // Left shift (multiply by 2)

            if(MSB != 0)
                multiplicand ^= 0x1B;
            multiplier >>= 1; // Right shift (divide by 2)
        }
        return result;
    }

    // each row (4 bytes) is moved in a horizontal shift of x
    // the first row -> moved zero position to the left, the second -> moved one position to the left, ect

    /**
     * ShiftRows: הזזת שורות במטריצת מצב שמאלה לפי מספר שורתן
     */
    private static void shiftRows(byte[] state) {

        for (int row = 1; row < 4; row++) {
            byte[] temp = Arrays.copyOfRange(state, row * 4, row * 4 + 4);
            rotWord(temp, row);
            System.arraycopy(temp, 0, state, row * 4, 4);
        }
    }

    /**
     * InverseShiftRows: הפעולה ההפוכה של ShiftRows
     */
    private static void inverseShiftRows(byte[] state) {
        for (int row = 1; row < 4; row++) {
            byte[] temp = Arrays.copyOfRange(state, row * 4, row * 4 + 4);
            inverse_rotWord(temp, row);
            System.arraycopy(temp, 0, state, row * 4, 4);
        }
    }

    // first operation - replace each byte with the one in the sodBox

    /**
     * SubBytes: החלפת כל בית לפי S-Box
     */
    private static void subByte(byte[] state) {
        for (int i = 0; i < state.length; i++) {
            state[i] = sodBox[state[i] & 0xff];
        }
    }

    /**
     * InverseSubByte: החלפת בתי מצב לפי Inverse S-Box
     */
    private static void inverseSubByte(byte[] state) {
        for (int i=0; i<state.length; i++)
            state[i] = inverseSodBox[state[i] & 0xff];
    }

    /**
     * הוספת PKCS#7 padding
     */
    public static byte[] addPadding(byte[] input, int blockSize){
        int padLength = blockSize - (input.length % blockSize);
        byte[] paddedInput = new byte[input.length + padLength];
        System.arraycopy(input, 0, paddedInput, 0, input.length);

        // fill the padding bytes
        for(int i=input.length; i<paddedInput.length; i++)
            paddedInput[i] = (byte) padLength; // padding byte = num of padding bytes

        return paddedInput;
    }

    /**
     * הסרת PKCS#7 padding
     */
    public static byte[] removePadding(byte[] input, int blockSize) {
        if (input.length == 0) {
            throw new IllegalArgumentException("Input cannot be empty");
        }

        // The padding byte should be the same as the number of padding bytes
        int paddingLength = input[input.length - 1] & 0xFF;

        if (paddingLength <= 0 || paddingLength > blockSize) {
            throw new IllegalArgumentException("Invalid padding length");
        }

        for (int i = input.length - paddingLength; i < input.length; i++) {
            if (input[i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Invalid padding bytes");
            }
        }

        return Arrays.copyOfRange(input, 0, input.length - paddingLength);
    }

    /**
     * Rcon: ערכי Round Constant לסיבובי Key Schedule
     */
    private static byte Rcon(int round) {
        if(round > 10 || round < 1)
            throw new IllegalArgumentException("Invalid round Number" + round);
        byte[] rconTable = new byte[] {
                (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08,
                (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80,
                (byte) 0x1B, (byte) 0x36
        };
        return rconTable[round - 1];
    }

    /**
     * AddRoundKey: XOR בין מצב למפתח הסיבוב
     */
    private static void addRoundKey(byte[] state, byte[] cipherKey) {

        for(int i=0; i<state.length; i++)
            // xor each byte separately
            state[i] = (byte) ((state[i] ^ cipherKey[i]) & 0xFF);
    }

}
