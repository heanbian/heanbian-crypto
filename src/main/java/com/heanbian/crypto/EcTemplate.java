package com.heanbian.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.Cipher;

public final class EcTemplate {

	private static final String KEY_ALGORITHM = "EC";
	private static final String CURVE_NAME = "secp256r1";
	private static final String TRANSFORMATION = "ECIES";

	private final PublicKey publicKey;
	private final PrivateKey privateKey;

	public EcTemplate() {
		this(generateKeyPair());
	}

	public EcTemplate(PublicKey publicKey) {
		this(publicKey, null);
	}

	public EcTemplate(PublicKey publicKey, PrivateKey privateKey) {
		if (publicKey == null && privateKey == null) {
			throw new IllegalArgumentException("publicKey 和 privateKey 不能同时为空");
		}
		this.publicKey = publicKey == null ? null : validatePublicKey(publicKey);
		this.privateKey = privateKey == null ? null : validatePrivateKey(privateKey);
	}

	public EcTemplate(String publicKeyString, String privateKeyString) {
		this(
				publicKeyString == null || publicKeyString.isBlank() ? null : deserializePublicKey(publicKeyString),
				privateKeyString == null || privateKeyString.isBlank() ? null : deserializePrivateKey(privateKeyString));
	}

	private EcTemplate(KeyPair keyPair) {
		this(keyPair.getPublic(), keyPair.getPrivate());
	}

	public String encrypt(String plaintext) {
		Objects.requireNonNull(plaintext, "plaintext不能为空");
		if (publicKey == null) {
			throw new IllegalStateException("当前实例不包含公钥，无法加密");
		}
		try {
			CryptoSupport.ensureBouncyCastle();
			Cipher cipher = Cipher.getInstance(TRANSFORMATION, CryptoSupport.BOUNCY_CASTLE);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
			return CryptoSupport.encodeBase64(cipherText);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("ECIES加密失败", ex);
		}
	}

	public String decrypt(String ciphertext) {
		if (privateKey == null) {
			throw new IllegalStateException("当前实例不包含私钥，无法解密");
		}
		try {
			CryptoSupport.ensureBouncyCastle();
			byte[] cipherBytes = CryptoSupport.decodeBase64(ciphertext, "EC密文");
			Cipher cipher = Cipher.getInstance(TRANSFORMATION, CryptoSupport.BOUNCY_CASTLE);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] plain = cipher.doFinal(cipherBytes);
			return new String(plain, StandardCharsets.UTF_8);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("ECIES解密失败", ex);
		}
	}

	public String getPublicKeyString() {
		if (publicKey == null) {
			throw new IllegalStateException("当前实例不包含公钥");
		}
		return CryptoSupport.encodeBase64(publicKey.getEncoded());
	}

	public String getPrivateKeyString() {
		if (privateKey == null) {
			throw new IllegalStateException("当前实例不包含私钥");
		}
		return CryptoSupport.encodeBase64(privateKey.getEncoded());
	}

	public static PublicKey deserializePublicKey(String base64Key) {
		try {
			CryptoSupport.ensureBouncyCastle();
			byte[] encoded = CryptoSupport.decodeBase64(base64Key, "EC公钥");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
			return java.security.KeyFactory.getInstance(KEY_ALGORITHM, CryptoSupport.BOUNCY_CASTLE)
					.generatePublic(keySpec);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("EC公钥反序列化失败", ex);
		}
	}

	public static PrivateKey deserializePrivateKey(String base64Key) {
		try {
			CryptoSupport.ensureBouncyCastle();
			byte[] encoded = CryptoSupport.decodeBase64(base64Key, "EC私钥");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
			return java.security.KeyFactory.getInstance(KEY_ALGORITHM, CryptoSupport.BOUNCY_CASTLE)
					.generatePrivate(keySpec);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("EC私钥反序列化失败", ex);
		}
	}

	private static KeyPair generateKeyPair() {
		try {
			CryptoSupport.ensureBouncyCastle();
			KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM, CryptoSupport.BOUNCY_CASTLE);
			generator.initialize(new ECGenParameterSpec(CURVE_NAME), CryptoSupport.secureRandom());
			return generator.generateKeyPair();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("EC密钥对生成失败", ex);
		}
	}

	private static PublicKey validatePublicKey(PublicKey key) {
		if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
			throw new IllegalArgumentException("不支持的EC公钥算法：" + key.getAlgorithm());
		}
		return key;
	}

	private static PrivateKey validatePrivateKey(PrivateKey key) {
		if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
			throw new IllegalArgumentException("不支持的EC私钥算法：" + key.getAlgorithm());
		}
		return key;
	}

}
