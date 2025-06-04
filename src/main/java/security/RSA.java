package security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * מחלקת RSA מממשת את אלגוריתם RSA עם אורך מפתח של 2048 ביט:
 *  - ייצור זוג מפתחות (p, q) וחשבון N = p*q ו-φ(N)
 *  - מפתח ציבורי e קבוע (65537) או מחושב אם אינו מתאים
 *  - מפתח פרטי d = e⁻¹ mod φ(N)
 *
 *  פונקציות מוצעות:
 *   • encrypt(byte[]): Padding פשוט + חישוב c = m^e mod N
 *   • decrypt(BigInteger): חישוב m = c^d mod N + הסרת padding
 *   • גרסאות סטטיות encrypt/decrypt לקבלת מפתח ו-N חיצוניים
 *   • derivePadding/removePadding לפירוק והוספת padding
 */

public class RSA {
    private static final SecureRandom random = new SecureRandom();
    public static final int BIT_LENGTH = 2048;               // גודל המפתח ביט
    private static final BigInteger PUBLIC_EXPONENT =       // e קבוע נפוץ
            BigInteger.valueOf(65537);

    private final BigInteger N;       // מודול: p*q
    private final BigInteger phiN;    // φ(N) = (p-1)*(q-1)
    private final BigInteger publicKey;
    private final BigInteger privateKey;

    /**
     * קונסטרקטור: יוצר שני ראשוניים p,q בגודל חצי מה-BIT_LENGTH,
     * מחשב N, φ(N), publicKey ו-privateKey = e⁻¹ mod φ(N).
     */
    public RSA() {
        BigInteger p = generateRandomPrime();
        BigInteger q = generateRandomPrime();
        this.N = p.multiply(q);
        this.phiN = phi(p, q);
        this.publicKey = generatePublicKey();
        this.privateKey = publicKey.modInverse(phiN);
    }

    /** מייצר ראשוני אקראי של BIT_LENGTH/2 ביט */
    private static BigInteger generateRandomPrime() {
        return BigInteger.probablePrime(BIT_LENGTH / 2, random);
    }

    /** יוצר את e (public exponent) כך ש-gcd(e, φ(N)) = 1 */
    private BigInteger generatePublicKey() {
        if (gcd(PUBLIC_EXPONENT, phiN).equals(BigInteger.ONE))
            return PUBLIC_EXPONENT;
        BigInteger e = BigInteger.valueOf(3);
        while (!gcd(e, phiN).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }
        return e;
    }

    /** מחזיר e (public exponent) */
    public BigInteger getPublicKey() { return publicKey; }
    /** מחזיר d (private exponent) */
    public BigInteger getPrivateKey() { return privateKey; }
    /** מחזיר N */
    public BigInteger getN() { return N; }

    /**
     * הצפנה של message:
     * 1. Padding פשוט של 16 בתים אקראיים
     * 2. המרה ל-BigInteger m
     * 3. חישוב c = m^e mod N
     */
    public BigInteger encrypt(byte[] message) {
        byte[] padded = addSimplePadding(message);
        BigInteger m = new BigInteger(1, padded);
        if (m.compareTo(N) >= 0)
            throw new IllegalArgumentException("Message too large");
        return m.modPow(publicKey, N);
    }

    /**
     * פענוח של cipherText:
     * 1. חישוב m = c^d mod N
     * 2. הסרת padding
     */
    public byte[] decrypt(BigInteger cipherText) {
        BigInteger m = cipherText.modPow(privateKey, N);
        return removeSimplePadding(m.toByteArray());
    }

    /** גרסה סטטית להצפנה עם מפתח ו-N חיצוניים */
    public static byte[] encrypt(byte[] message, BigInteger pubKey, BigInteger N) {
        byte[] padded = addSimplePadding(message);
        BigInteger m = new BigInteger(1, padded);
        if (m.compareTo(N) >= 0)
            throw new IllegalArgumentException("Message too large");
        return m.modPow(pubKey, N).toByteArray();
    }

    /** גרסה סטטית לפענוח עם מפתח פרטי ו-N חיצוניים */
    public static byte[] decrypt(byte[] cipher, BigInteger privKey, BigInteger N) {
        BigInteger c = new BigInteger(1, cipher);
        if (c.compareTo(N) >= 0)
            throw new IllegalArgumentException("Cipher too large");
        BigInteger m = c.modPow(privKey, N);
        return removeSimplePadding(m.toByteArray());
    }

    /** מוסיף padding פשוט: 16 בתים אקראיים לפני ההודעה */
    private static byte[] addSimplePadding(byte[] msg) {
        byte[] pad = new byte[16];
        random.nextBytes(pad);
        byte[] out = Arrays.copyOf(pad, pad.length + msg.length);
        System.arraycopy(msg, 0, out, pad.length, msg.length);
        return out;
    }

    /** מסיר את 16 הבתים הראשונים (padding) */
    private static byte[] removeSimplePadding(byte[] data) {
        if (data.length <= 16)
            throw new IllegalArgumentException("Invalid decrypted length");
        return Arrays.copyOfRange(data, 16, data.length);
    }

    /** gcd קלסי באמצעות אלגוריתם אוקלידס */
    private BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger t = b;
            b = a.mod(b);
            a = t;
        }
        return a;
    }

    /** φ(N) = (p-1)*(q-1) */
    private BigInteger phi(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    /** דוגמת main לייצור מפתח, הצפנה ופענוח */
    public static void main(String[] args) {
        RSA rsa = new RSA();
        String msg = "Hello RSA!";
        BigInteger enc = rsa.encrypt(msg.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted: " + enc);
        byte[] dec = rsa.decrypt(enc);
        System.out.println("Decrypted: " + new String(dec, StandardCharsets.UTF_8));
    }
}
