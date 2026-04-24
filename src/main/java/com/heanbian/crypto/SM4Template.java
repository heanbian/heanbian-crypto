package com.heanbian.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class SM4Template {

	private static final String KEY_ALGORITHM = "SM4";
	private static final String TRANSFORMATION = "SM4/GCM/NoPadding";
	private static final int KEY_LENGTH_BYTE = 16;
	private static final int KEY_LENGTH_BIT = 128;
	private static final int IV_LENGTH_BYTE = 12;
	private static final int TAG_LENGTH_BIT = 128;
	private static final int MIN_CIPHERTEXT_LENGTH = IV_LENGTH_BYTE + 16;

	private final SecretKey key;

	public SM4Template() {
		this(generateSecretKey());
	}

	public SM4Template(String keyText) {
		this(restoreSecretKey(keyText));
	}

	private SM4Template(SecretKey key) {
		this.key = Objects.requireNonNull(key, "SM4密钥不能为空");
		CryptoSupport.requireAnyLength(key.getEncoded(), "SM4密钥", KEY_LENGTH_BYTE);
	}

	public static String generateKey() {
		return CryptoSupport.encodeBase64(generateSecretKey().getEncoded());
	}

	public String getKeyString() {
		return CryptoSupport.encodeBase64(key.getEncoded());
	}

	public String encrypt(String plainText) {
		Objects.requireNonNull(plainText, "plainText不能为空");
		try {
			byte[] iv = new byte[IV_LENGTH_BYTE];
			CryptoSupport.secureRandom().nextBytes(iv);

			Cipher cipher = Cipher.getInstance(TRANSFORMATION, CryptoSupport.BOUNCY_CASTLE);
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length);
			buffer.put(iv);
			buffer.put(encrypted);

			return CryptoSupport.encodeBase64(buffer.array());
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("SM4加密失败", ex);
		}
	}

	/**
	 * 兼容旧签名：支持传入 Base64Url 密钥，也兼容旧版16字节原始字符串密钥。
	 */
	public String encrypt(String plainText, String keyText) {
		return new SM4Template(keyText).encrypt(plainText);
	}

	public String decrypt(String encryptedText) {
		try {
			byte[] payload = CryptoSupport.decodeBase64(encryptedText, "SM4密文");
			CryptoSupport.requireAtLeast(payload, "SM4密文", MIN_CIPHERTEXT_LENGTH);

			ByteBuffer buffer = ByteBuffer.wrap(payload);
			byte[] iv = new byte[IV_LENGTH_BYTE];
			buffer.get(iv);

			byte[] encrypted = new byte[buffer.remaining()];
			buffer.get(encrypted);

			Cipher cipher = Cipher.getInstance(TRANSFORMATION, CryptoSupport.BOUNCY_CASTLE);
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			byte[] plain = cipher.doFinal(encrypted);
			return new String(plain, StandardCharsets.UTF_8);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("SM4解密失败", ex);
		}
	}

	/**
	 * 兼容旧签名：支持传入 Base64Url 密钥，也兼容旧版16字节原始字符串密钥。
	 */
	public String decrypt(String encryptedText, String keyText) {
		return new SM4Template(keyText).decrypt(encryptedText);
	}

	private static SecretKey generateSecretKey() {
		try {
			CryptoSupport.ensureBouncyCastle();
			KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, CryptoSupport.BOUNCY_CASTLE);
			keyGenerator.init(KEY_LENGTH_BIT, CryptoSupport.secureRandom());
			return keyGenerator.generateKey();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("SM4密钥生成失败", ex);
		}
	}

	private static SecretKey restoreSecretKey(String keyText) {
		String normalized = CryptoSupport.requireText(keyText, "SM4密钥");

		// 优先支持 Base64Url 编码的 16 字节密钥
		try {
			byte[] decoded = Base64.getUrlDecoder().decode(normalized);
			if (decoded.length == KEY_LENGTH_BYTE) {
				return new SecretKeySpec(decoded, KEY_ALGORITHM);
			}
		} catch (IllegalArgumentException ignore) {
			// 忽略，继续尝试旧版原始字符串方案
		}

		// 兼容旧版：16字节原始字符串
		byte[] rawBytes = normalized.getBytes(StandardCharsets.UTF_8);
		if (rawBytes.length == KEY_LENGTH_BYTE) {
			return new SecretKeySpec(rawBytes, KEY_ALGORITHM);
		}

		throw new IllegalArgumentException("SM4密钥必须是16字节原始字符串，或Base64Url编码后的16字节密钥");
	}

}
