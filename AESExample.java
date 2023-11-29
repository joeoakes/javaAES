import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESExample {

    // Method for AES encryption
    public static String encrypt(String strToEncrypt, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
    }

    // Method for AES decryption
    public static String decrypt(String strToDecrypt, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
    }

    public static void main(String[] args) {
        try {
            // Generate a SecretKey for AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128); // Key size
            SecretKey secretKey = keyGenerator.generateKey();

            // Example usage
            String originalString = "Hello, World!";
            String encryptedString = encrypt(originalString, secretKey);
            String decryptedString = decrypt(encryptedString, secretKey);

            System.out.println("Original: " + originalString);
            System.out.println("Encrypted: " + encryptedString);
            System.out.println("Decrypted: " + decryptedString);
        } catch (Exception e) {
            System.err.println("Error during encryption/decryption: " + e.getMessage());
        }
    }
}
