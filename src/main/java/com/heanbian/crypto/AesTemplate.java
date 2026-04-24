package com.heanbian.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesTemplate {

	private static final String KEY_ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES/GCM/NoPadding";
	private static final int DEFAULT_KEY_LENGTH_BIT = 256;
	private static final int IV_LENGTH_BYTE = 12;
	private static final int TAG_LENGTH_BIT = 128;
	private static final int MIN_CIPHERTEXT_LENGTH = IV_LENGTH_BYTE + 16;

	private final SecretKey key;

	public AesTemplate() {
		this(generateSecretKey());
	}

	public AesTemplate(String base64Key) {
		this(restoreSecretKey(base64Key));
	}

	private AesTemplate(SecretKey key) {
		this.key = Objects.requireNonNull(key, "AES密钥不能为空");
		CryptoSupport.requireAnyLength(key.getEncoded(), "AES密钥", 16, 24, 32);
	}

	public static String generateKey() {
		return CryptoSupport.encodeBase64(generateSecretKey().getEncoded());
	}

	public String getKeyString() {
		return CryptoSupport.encodeBase64(key.getEncoded());
	}

	public String encrypt(String plaintext) {
		Objects.requireNonNull(plaintext, "plaintext不能为空");
		try {
			byte[] iv = new byte[IV_LENGTH_BYTE];
			CryptoSupport.secureRandom().nextBytes(iv);

			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
			ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length);
			buffer.put(iv);
			buffer.put(encrypted);

			return CryptoSupport.encodeBase64(buffer.array());
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("AES加密失败", ex);
		}
	}

	public String decrypt(String ciphertext) {
		try {
			byte[] payload = CryptoSupport.decodeBase64(ciphertext, "AES密文");
			CryptoSupport.requireAtLeast(payload, "AES密文", MIN_CIPHERTEXT_LENGTH);

			ByteBuffer buffer = ByteBuffer.wrap(payload);
			byte[] iv = new byte[IV_LENGTH_BYTE];
			buffer.get(iv);

			byte[] encrypted = new byte[buffer.remaining()];
			buffer.get(encrypted);

			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			byte[] plain = cipher.doFinal(encrypted);
			return new String(plain, StandardCharsets.UTF_8);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("AES解密失败", ex);
		}
	}

	SecretKey secretKey() {
		return key;
	}

	private static SecretKey generateSecretKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
			keyGenerator.init(DEFAULT_KEY_LENGTH_BIT);
			return keyGenerator.generateKey();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("AES密钥生成失败", ex);
		}
	}

	private static SecretKey restoreSecretKey(String base64Key) {
		byte[] keyBytes = CryptoSupport.decodeBase64(base64Key, "AES密钥");
		CryptoSupport.requireAnyLength(keyBytes, "AES密钥", 16, 24, 32);
		return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
	}

}
