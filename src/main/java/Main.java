import crypto.MasterKeyManager;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) {
        try {
            // 1. בחר סיסמה (יכולה להגיע מ-args, GUI, וכו')
            String passphrase = "myVerySecretPass";
            byte[] passphraseBytes = passphrase.getBytes(StandardCharsets.UTF_8);
            System.out.println("Original key (hex): ," + bytesToHex(passphraseBytes));

            // 2. אתחל את MasterKeyManager (יעשה את כל העול: load או generate)
            MasterKeyManager mkm = new MasterKeyManager(passphraseBytes);

            // 3. קבל את raw master key לשימוש חיצוני
            byte[] masterKey = mkm.getMasterKeyRaw();

            // 4. העבר ל-DataKeyManager וכד' (לפי הארכיטקטורה שלך)
            System.out.println("Master Key (hex): " + bytesToHex(masterKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // שיטה פשוטה להדפסת מערך בתים ב-hex (לבדיקה בלבד)
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
