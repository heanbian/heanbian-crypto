package com.heanbian.block.crypto;

import java.nio.charset.StandardCharsets;
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

public class RsaTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String ALGORITHM = "RSA";
	private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	private PublicKey publicKey;
	private PrivateKey privateKey;

	public RsaTemplate() {
		KeyPair keyPair = generateKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	private KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
			generator.initialize(2048);
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to generate RSA key pair", e);
		}
	}

	public String encrypt(String content) {
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
			byte[] encryptedBytes = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException("Encryption failed", e);
		}
	}

	public String decrypt(String encryptedContent) {
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedContent));
			return new String(decryptedBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("Decryption failed", e);
		}
	}

	public String getPublicKeyString() {
		return Base64.getUrlEncoder().encodeToString(this.publicKey.getEncoded());
	}

	public String getPrivateKeyString() {
		return Base64.getUrlEncoder().encodeToString(this.privateKey.getEncoded());
	}

	public PublicKey loadPublicKey(String publicKeyString) {
		try {
			byte[] encodedKey = Base64.getUrlDecoder().decode(publicKeyString);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
			return factory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load public key", e);
		}
	}

	public PrivateKey loadPrivateKey(String privateKeyString) {
		try {
			byte[] encodedKey = Base64.getUrlDecoder().decode(privateKeyString);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
			return factory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load private key", e);
		}
	}

}