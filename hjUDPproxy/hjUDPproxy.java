/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import java.util.Base64;
import Utils.AesGcmUtils;
import Utils.Chacha20Utils;
import Utils.OTPUtils;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        // Read config
        InputStream inputStream = new FileInputStream("config.properties");
        if (inputStream == null) {
                System.err.println("Configuration file not found!");
                System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");
        String mode = properties.getProperty("decryptionMode", "AES-GCM");
        String keyString = properties.getProperty("decryptionKey", "0123456789abcdef0123456789abcdef");

        // Prepare key bytes
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        byte[] seedBytes = null;
        SecretKey aesKey = null;
        SecretKey chachaKey = null;
        if (mode.equalsIgnoreCase("AES-GCM")) {
            System.out.println("Proxy Using AES-GCM decryption mode");
            // Use first 16 bytes for the key
            byte[] aesKeyBytes = new byte[16];
            System.arraycopy(keyBytes, 0, aesKeyBytes, 0, Math.min(keyBytes.length, 16));
            String base64AesKey = Base64.getEncoder().encodeToString(aesKeyBytes);
            aesKey = new AesGcmUtils().generateKey(base64AesKey);
        } else if (mode.equalsIgnoreCase("CHACHA20")) {
            //use the whole thing for the key, assuming 32 bytes
            System.out.println("Proxy Using CHACHA20 decryption mode");
            String base64ChaChaKey = Base64.getEncoder().encodeToString(keyBytes);
            chachaKey = Chacha20Utils.generateKey(base64ChaChaKey);
        } else if (mode.equalsIgnoreCase("OTP")) {
            System.out.println("Proxy Using OTP decryption mode");
            String otpSeedString = properties.getProperty("OTPSeed");
            seedBytes = Base64.getDecoder().decode(otpSeedString);
        } else {
            System.err.println("Proxy Unknown decryption mode: " + mode);
            System.exit(1);
        }
         SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
   
        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);  // receive encrypted datagram

            byte[] encryptedData = new byte[inPacket.getLength()];
            System.arraycopy(inPacket.getData(), 0, encryptedData, 0, inPacket.getLength());
            byte[] decryptedData = null;
            try {
                switch (mode.toUpperCase()) {
                    case "AES-GCM":
                        decryptedData = new AesGcmUtils().decrypt(aesKey, encryptedData);
                        break;
                    case "CHACHA20":
                        if (chachaKey != null) {
                            decryptedData = Chacha20Utils.decrypt(chachaKey, encryptedData);
                        }
                        break;
                    case "OTP":
                        // Extract 4-byte big-endian segment index prepended by server
                        int segmentIndex = ((encryptedData[0] & 0xFF) << 24)
                                         | ((encryptedData[1] & 0xFF) << 16)
                                         | ((encryptedData[2] & 0xFF) << 8)
                                         |  (encryptedData[3] & 0xFF);
                        byte[] cipherPayload = java.util.Arrays.copyOfRange(encryptedData, 4, encryptedData.length);
                        decryptedData = OTPUtils.otpDprgXor(cipherPayload, keyBytes, seedBytes, segmentIndex);
                        break;
                    default:
                        System.err.println("Proxy Unknown decryption mode: " + mode);
                        continue;
                }
            } catch (Exception e) {
                System.err.println("[Proxy] Decryption failed: " + e.getMessage());
                continue;
            }
            System.out.print(".");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(decryptedData, decryptedData.length, outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

}
