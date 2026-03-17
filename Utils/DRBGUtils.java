package Utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class DRBGUtils {

    private final byte[] key;
    private final byte[] seed;

    public DRBGUtils(byte[] key, byte[] seed) {
        this.key = key;
        this.seed = seed;
    }

    // Generate keystream for a segment, using segment index for sync.
    // Seeds a fresh HMAC-DRBG instance with key || seed || segmentIndex
    // so both server and proxy produce the same keystream deterministically.

    /*
    Generates a keystream for each segment, using the index,, seeds a HMAC-DRBG with key|| seed|| segmentIndex
    so that the server and the proxy can reach the same result 
    */
    public byte[] generateKeystream(int segmentIndex, int length) throws Exception {
        byte[] entropyInput = new byte[key.length + seed.length + 4];
        System.arraycopy(key, 0, entropyInput, 0, key.length);
        System.arraycopy(seed, 0, entropyInput, key.length, seed.length);
        byte[] segBytes = intToBytes(segmentIndex);
        System.arraycopy(segBytes, 0, entropyInput, key.length + seed.length, 4);

        HmacDRBG drbg = new HmacDRBG(entropyInput);
        return drbg.generate(length);
    }

    private static byte[] intToBytes(int value) {
        return new byte[] {
            (byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
        };
    }

    private static class HmacDRBG {

        private byte[] K;
        private byte[] V;
        private final Mac mac;

        HmacDRBG(byte[] entropyInput) throws Exception {
            mac = Mac.getInstance("HmacSHA256");
            K = new byte[32];              // initially 0x00
            V = new byte[32];
            Arrays.fill(V, (byte) 0x01);   // V initialized to 0x01
            update(entropyInput);
        }

        private byte[] hmac(byte[] key, byte[] data) throws Exception {
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        }

        private void update(byte[] providedData) throws Exception {
            byte[] input = new byte[V.length + 1 + providedData.length];
            System.arraycopy(V, 0, input, 0, V.length);
            input[V.length] = 0x00;
            System.arraycopy(providedData, 0, input, V.length + 1, providedData.length);
            K = hmac(K, input);
            V = hmac(K, V);

            if (providedData.length > 0) {
                input = new byte[V.length + 1 + providedData.length];
                System.arraycopy(V, 0, input, 0, V.length);
                input[V.length] = 0x01;
                System.arraycopy(providedData, 0, input, V.length + 1, providedData.length);
                K = hmac(K, input);
                V = hmac(K, V);
            }
        }

        byte[] generate(int length) throws Exception {
            byte[] output = new byte[length];
            int pos = 0;
            while (pos < length) {
                V = hmac(K, V);
                int copyLength = Math.min(V.length, length - pos);
                System.arraycopy(V, 0, output, pos, copyLength);
                pos += copyLength;
            }
            update(new byte[0]); // update internal state
            return output;
        }
    }
}
