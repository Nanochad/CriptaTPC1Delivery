package Utils;

public class OTPUtils {
    public static byte[] otpXor(byte[] data, byte[] key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return out;
    }

    public static byte[] otpDprgXor(byte[] data, byte[] key, byte[] seed, int segmentIndex) throws Exception {
        Utils.DRBGUtils dprg = new Utils.DRBGUtils(key, seed);
        byte[] keystream = dprg.generateKeystream(segmentIndex, data.length);
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ keystream[i]);
        }
        return out;
    }
}
