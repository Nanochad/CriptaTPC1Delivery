package Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class Chacha20Utils {

    private static final String ALGO = "ChaCha20-Poly1305";
    private static final int NONCE_LEN = 12;
    private static final SecureRandom random = new SecureRandom();

    public static byte[] encrypt(SecretKey key, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        random.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(ALGO);
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] result = new byte[NONCE_LEN + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, NONCE_LEN);
        System.arraycopy(ciphertext, 0, result, NONCE_LEN, ciphertext.length);
        return result;
    }

    public static byte[] decrypt(SecretKey key, byte[] input) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        System.arraycopy(input, 0, nonce, 0, NONCE_LEN);

        byte[] ciphertext = new byte[input.length - NONCE_LEN];
        System.arraycopy(input, NONCE_LEN, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(ALGO);
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        return cipher.doFinal(ciphertext);
    }

    public static SecretKey generateKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, ALGO);
    }

}
