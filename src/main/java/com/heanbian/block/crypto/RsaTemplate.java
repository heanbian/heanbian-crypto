package com.heanbian.block.crypto;

import static java.util.Objects.requireNonNull;

import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * RSA加解密
 * 
 * @author Heanbian
 *
 */
public final class RsaTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private RsaTemplate() {
	}

	private static final String ALG = "RSA";

	public static KeyPair getKeyPair() {
		KeyPairGenerator k;
		try {
			k = KeyPairGenerator.getInstance(ALG);
			k.initialize(2048);
			return k.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String getPublicKey(KeyPair keyPair) {
		requireNonNull(keyPair, "keyPair must not be null");
		return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
	}

	public static String getPrivateKey(KeyPair keyPair) {
		requireNonNull(keyPair, "keyPair must not be null");
		return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
	}

	public static PublicKey getPublicKey(String encodedPublicKey) {
		requireNonNull(encodedPublicKey, "encodedPublicKey must not be null");

		byte[] encodedKey = Base64.getDecoder().decode(encodedPublicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance(ALG);
			return factory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static PrivateKey getPrivateKey(String encodedPrivateKey) {
		requireNonNull(encodedPrivateKey, "encodedPrivateKey must not be null");

		byte[] encodedKey = Base64.getDecoder().decode(encodedPrivateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance(ALG);
			return factory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String encrypt(String content, PublicKey publicKey) {
		requireNonNull(content, "content must not be null");
		requireNonNull(publicKey, "publicKey must not be null");

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encoded = cipher.doFinal(content.getBytes(Charset.defaultCharset()));
			return Base64.getEncoder().encodeToString(encoded);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static String decrypt(String content, PrivateKey privateKey) {
		requireNonNull(content, "content must not be null");
		requireNonNull(privateKey, "privateKey must not be null");

		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decoded = cipher.doFinal(Base64.getDecoder().decode(content));
			return new String(decoded, Charset.defaultCharset());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}