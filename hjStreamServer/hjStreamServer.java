/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Properties;
import Utils.AesGcmUtils;
import Utils.Chacha20Utils;
import Utils.OTPUtils;

class hjStreamServer {
	private static AesGcmUtils aes = null;

	public static void main(String[] args) throws Exception {
		// Read config
		Properties properties = new Properties();
		try (FileInputStream fis = new FileInputStream("../hjUDPproxy/config.properties")) {
			properties.load(fis);
		}
		String mode = properties.getProperty("decryptionMode"); 
		String keyString = properties.getProperty("decryptionKey");

		byte[] keyBytes = Base64.getDecoder().decode(keyString);
		byte[] seedBytes = null;
		SecretKey chachaKey = null;
		SecretKey aesKey = null;
		if (mode.equalsIgnoreCase("AES-GCM")) {
			System.out.println("Server Using AES-GCM encryption mode");
			aes = new AesGcmUtils();
			// Use first 16 bytes for AES-GCM
			byte[] aesKeyBytes = new byte[16];
			System.arraycopy(keyBytes, 0, aesKeyBytes, 0, Math.min(keyBytes.length, 16));
			String base64AesKey = Base64.getEncoder().encodeToString(aesKeyBytes);
			aesKey = aes.generateKey(base64AesKey);
		} else if (mode.equalsIgnoreCase("CHACHA20")) {
			System.out.println("Server Using CHACHA20 encryption mode");
			if (keyBytes.length != 32) {
				System.err.println("ChaCha20 key must be exactly 32 bytes (256 bits)!");
				System.exit(1);
			}
			String base64ChaChaKey = Base64.getEncoder().encodeToString(keyBytes);
			chachaKey = Chacha20Utils.generateKey(base64ChaChaKey);
		} else if (mode.equalsIgnoreCase("OTP")) {
			System.out.println("Server Using OTP encryption mode");
			String otpSeedString = properties.getProperty("OTPSeed");
			seedBytes = Base64.getDecoder().decode(otpSeedString);
		} else {
			System.err.println("Server Unknown encryption mode: " + mode);
			System.exit(1);
		}

		
		if (args.length != 3)
		{
			System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port>");
			System.out.println("        or: mySend <movie> <ip-unicast-address> <port>");
			System.exit(-1);
		}
      
		int size;
		int csize = 0;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
		byte[] buff = new byte[4096];

		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); // Ref. time 
		long q0 = 0;


	        // Movies are encoded in .dat files, where each
          	// frame is encoded in a real-time sequence of MP4 frames 
         	// Somewhat an FFMPEG4 playing scheme .. Dont worry
		
		// Each frame has:
		// Short size || Long Timestamp || byte[] EncodedMP4Frame
		// You can read (frame by frame to transmit ...
		// But you must folow the "real-time" encoding conditions

		// OK let's do it !

		while ( g.available() > 0 ) {
			size = g.readShort(); // size of the frame
			csize=csize+size;
			time = g.readLong();  // timestamp of the frame
			if ( count == 0 ) q0 = time; // ref. time in the stream
			count += 1;
			g.readFully(buff, 0, size );

			// Encrypt the frame data before sending
			byte[] encrypted = null;
			byte[] frameData = java.util.Arrays.copyOf(buff, size);
			switch (mode.toUpperCase()) {
				case "AES-GCM":
					if (aes == null) {
						aes = new AesGcmUtils();
					}
					encrypted = aes.encrypt(aesKey, frameData);
					break;
				case "CHACHA20":
					if (chachaKey != null) {
						encrypted = Chacha20Utils.encrypt(chachaKey, frameData);
					}
					break;
				case "OTP":
					byte[] payload = OTPUtils.otpDprgXor(frameData, keyBytes, seedBytes, count);
					// Prepend 4-byte big-endian segment index so the proxy can sync
					encrypted = new byte[4 + payload.length];
					encrypted[0] = (byte)(count >>> 24);
					encrypted[1] = (byte)(count >>> 16);
					encrypted[2] = (byte)(count >>> 8);
					encrypted[3] = (byte)(count);
					System.arraycopy(payload, 0, encrypted, 4, payload.length);
					break;
				default:
					System.err.println("Server Unknown encryption mode: " + mode);
					continue;
			}
			p.setData(encrypted, 0, encrypted.length);
			p.setSocketAddress( addr );

			long t = System.nanoTime(); // what time is it?
			// Decision about the right time to transmit
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
			// Send encrypted datagram (udp packet)
			s.send(p);
			// Just for awareness ... (debug)
			System.out.print( ":" );
		}

		long tend = System.nanoTime(); // "The end" time 
                System.out.println();
		System.out.println("DONE! all frames sent: "+ count);

		long duration=(tend-t0)/1000000000;
		System.out.println("Movie duration "+ duration + " s");
		System.out.println("Throughput "+ count/duration + " fps");
     	        System.out.println("Throughput "+ (8*(csize)/duration)/1000 + " Kbps");

	}
}



