package com.test;

import java.io.File;
import java.security.interfaces.RSAPublicKey;

public class RsaWrap {	

	public static void main(String[] args) throws Exception {		
		if (args == null || args.length != 3) {
			System.out.println("Example:");
			System.out.println("\t\t java -jar <jar-file> <wrapping-key> <key-to-wrap (PKCS8 if RSA PrivateKey) > <wrapped-output-key>");
			System.out.println("PEM to PKCS8 command:"); 
			System.out.println("\t\t openssl pkcs8 -topk8 -inform PEM -outform DER -in private-key.pem -out private-key.der -nocrypt");
			return;
		}

		File wrappingKeyPath = new File(args[0].trim());
		if (!wrappingKeyPath.exists()) {
			System.out.println("Error: Wrapping key does not exist at - " + args[0]);
			return;
		}

		File keyToWrapPath = new File(args[1].trim());
		if (!keyToWrapPath.exists()) {
			System.out.println("Error: Key to wrap does not exist at - " + args[1]);
			return;
		}

		RSAPublicKey wrappingKey = Helper.readRSAPublicKeyFromFile(args[0].trim());
		
		byte[] keyToWrap = Helper.readFileAsBytes(args[1].trim());		
		byte[] wrappedKey = Helper.wrapWithRsaOaepAesSha256(wrappingKey, keyToWrap);
				
		System.out.println("Writing to file - " + args[2]);
		Helper.writeToFile(args[2].trim(), wrappedKey);
		System.out.println("--- SUCCESS ---");
	}

}
