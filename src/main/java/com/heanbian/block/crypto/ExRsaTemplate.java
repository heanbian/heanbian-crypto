package com.heanbian.block.crypto;

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

public class ExRsaTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	static final String ALG = "RSA";
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public ExRsaTemplate() {
		KeyPair keyPair = getKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	public KeyPair getKeyPair() {
		KeyPairGenerator k;
		try {
			k = KeyPairGenerator.getInstance(ALG);
			k.initialize(2048);
			return k.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public String encrypt(String content) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
			byte[] encoded = cipher.doFinal(content.getBytes());
			return Base64.getEncoder().encodeToString(encoded);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String content) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] decoded = cipher.doFinal(Base64.getDecoder().decode(content));
			return new String(decoded, Charset.defaultCharset());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String getPublicKey() {
		return Base64.getEncoder().encodeToString(this.publicKey.getEncoded());
	}

	public String getPrivateKey() {
		return Base64.getEncoder().encodeToString(this.privateKey.getEncoded());
	}

	public PublicKey getPublicKey(String publicKey) {
		byte[] encodedKey = Base64.getDecoder().decode(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance(ALG);
			return factory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public PrivateKey getPrivateKey(String privateKey) {
		byte[] encodedKey = Base64.getDecoder().decode(privateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance(ALG);
			return factory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}