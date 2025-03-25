package com.heanbian.block.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AesTemplate {

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static final String DEFAULT_ALGORITHM = "AES";
	private static final String DEFAULT_PADDING = "AES/CBC/PKCS7Padding";
	private static final int KEY_LENGTH_BYTES = 16;
	private static final int IV_LENGTH_BYTES = 16;

	private static final String DEFAULT_KEY = "1234567890abcdef";
	private static final String DEFAULT_IV = "1234567890abcdef";

	private final String padding;
	private final SecretKeySpec secretKeySpec;
	private final IvParameterSpec ivParameterSpec;

	public AesTemplate() {
		this(DEFAULT_ALGORITHM, DEFAULT_KEY, DEFAULT_IV, DEFAULT_PADDING);
	}

	public AesTemplate(byte[] key, byte[] iv) {
		this(DEFAULT_ALGORITHM, key, iv, DEFAULT_PADDING);
	}

	public AesTemplate(String alg, String key, String iv, String pad) {
		this(alg, validateByteLength(key, KEY_LENGTH_BYTES, "Key"), validateByteLength(iv, IV_LENGTH_BYTES, "IV"), pad);
	}

	public AesTemplate(String alg, byte[] key, byte[] iv, String pad) {
		validateLength(key, KEY_LENGTH_BYTES, "Key");
		validateLength(iv, IV_LENGTH_BYTES, "IV");
		this.padding = pad;
		this.secretKeySpec = new SecretKeySpec(key, alg);
		this.ivParameterSpec = new IvParameterSpec(iv);
	}

	private static byte[] validateByteLength(String input, int expectedLength, String paramName) {
		if (input == null) {
			throw new IllegalArgumentException(paramName + "不能为空");
		}
		byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
		if (bytes.length != expectedLength) {
			throw new IllegalArgumentException(
					paramName + " must produce " + expectedLength + " bytes when UTF-8 encoded");
		}
		return bytes;
	}

	private static void validateLength(byte[] input, int expectedLength, String paramName) {
		if (input == null || input.length != expectedLength) {
			throw new IllegalArgumentException(paramName + " must be " + expectedLength + " bytes");
		}
	}

	public static byte[] generateRandomKey() {
		byte[] key = new byte[KEY_LENGTH_BYTES];
		new SecureRandom().nextBytes(key);
		return key;
	}

	public static byte[] generateRandomIv() {
		byte[] iv = new byte[IV_LENGTH_BYTES];
		new SecureRandom().nextBytes(iv);
		return iv;
	}

	public String encrypt(String text) {
		if (text == null) {
			throw new IllegalArgumentException("text不能为空");
		}
		try {
			Cipher cipher = Cipher.getInstance(padding);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException("加密失败", e);
		}
	}

	public String decrypt(String encryptedText) {
		if (encryptedText == null) {
			throw new IllegalArgumentException("encryptedText不能为空");
		}
		try {
			Cipher cipher = Cipher.getInstance(padding);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] decodedBytes = Base64.getUrlDecoder().decode(encryptedText);
			byte[] decryptedBytes = cipher.doFinal(decodedBytes);
			return new String(decryptedBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("解密失败", e);
		}
	}

}