package com.test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;

import org.bouncycastle.crypto.KeyWrapper;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsKeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsRSA.WrapParameters;
import org.bouncycastle.crypto.fips.FipsSHS;

public final class Helper {

	public static Path writeToFile(String filename, byte[] dataToWrite) throws IOException {
		File outputFile = new File(filename);
		return Files.write(outputFile.toPath(), dataToWrite);
	}
	
	public static byte[] readFileAsBytes(String filename) throws Exception {		
		return Files.readAllBytes(Paths.get(filename));
	}	
		
	public static RSAPublicKey readRSAPublicKeyFromFile(String filename) throws Exception {
		String fileContents = new String(readFileAsBytes(filename));	
		String publicKeyPEM = fileContents.replace("-----BEGIN PUBLIC KEY-----\n", "");
		publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

		byte[] decoded = org.bouncycastle.util.encoders.Base64.decode(publicKeyPEM.trim());

		X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) kf.generatePublic(spec);
	}
	
	public static RSAPublicKey readRSAPublicKeyFromString(String publicKeyString) throws Exception {
		String publicKeyPEM = publicKeyString.replace("-----BEGIN PUBLIC KEY-----", "");
		publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
		publicKeyPEM = publicKeyPEM.replace("\\s", "");           
		byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
	}
	
	public static Key generateAes(int size) throws GeneralSecurityException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(size);
		return keyGen.generateKey();
	}
	
	@SuppressWarnings({"unchecked", "rawtypes"})
	public static byte[] wrapWithRsaOaepAesSha256(RSAPublicKey wrappingKey, byte[] keyToWrap) {		
		try {
			byte[] randomAESKey = Helper.generateAes(32 * 8).getEncoded();

			AsymmetricRSAPublicKey rsaPublicKey = new AsymmetricRSAPublicKey(FipsRSA.ALGORITHM, wrappingKey.getModulus(), wrappingKey.getPublicExponent());
			org.bouncycastle.crypto.fips.FipsRSA.WrapParameters wrapParameters = FipsRSA.WRAP_OAEP.withDigest(FipsSHS.Algorithm.SHA256);
			org.bouncycastle.crypto.fips.FipsRSA.KeyWrapOperatorFactory rsaAesEncrypter = new org.bouncycastle.crypto.fips.FipsRSA.KeyWrapOperatorFactory();            			

			FipsKeyWrapperUsingSecureRandom<WrapParameters> keyWrapper = (FipsKeyWrapperUsingSecureRandom)rsaAesEncrypter.createKeyWrapper(
					rsaPublicKey, wrapParameters).withSecureRandom(SecureRandom.getInstanceStrong());
			byte[] wrappedAESKeyBytes = keyWrapper.wrap(randomAESKey, 0, randomAESKey.length);

			SymmetricKey aesWrappingKey = new SymmetricSecretKey(FipsAES.ALGORITHM, randomAESKey);
			org.bouncycastle.crypto.fips.FipsAES.KeyWrapOperatorFactory aesKeyOperatorFactory = new org.bouncycastle.crypto.fips.FipsAES.KeyWrapOperatorFactory();
			KeyWrapper<FipsAES.WrapParameters> wrapper = aesKeyOperatorFactory.createKeyWrapper(aesWrappingKey, FipsAES.KWP);
			byte[] wrappedKey = wrapper.wrap(keyToWrap, 0, keyToWrap.length);

			return org.bouncycastle.util.Arrays.concatenate(wrappedAESKeyBytes, wrappedKey);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
