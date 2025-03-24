package com.heanbian.block.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class LargeAesTemplate {

	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int TAG_LENGTH_BIT = 128; // GCM 认证标签长度
	private static final int IV_LENGTH_BYTE = 12; // GCM 推荐 IV 长度
	private static final int KEY_LENGTH_BIT = 256; // AES-256

	private final String base64Key;

	public LargeAesTemplate() {
		this.base64Key = generateKey();
	}

	public LargeAesTemplate(String base64Key) {
		this.base64Key = base64Key;
	}

	public SecretKey initKey() {
		if (base64Key == null) {
			throw new RuntimeException("base64Key 不能为空");
		}

		byte[] decodedKey = Base64.getUrlDecoder().decode(base64Key);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
	}

	public String generateKey() {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(KEY_LENGTH_BIT);
			SecretKey key = keyGen.generateKey();
			return Base64.getUrlEncoder().encodeToString(key.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException("生成密钥失败", e);
		}
	}

	public String encrypt(String plaintext) {
		try {
			SecretKey key = initKey();
			byte[] iv = new byte[IV_LENGTH_BYTE];
			new SecureRandom().nextBytes(iv);
			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
			byte[] encryptedBytes = new byte[iv.length + cipher.getOutputSize(plainBytes.length)];

			System.arraycopy(iv, 0, encryptedBytes, 0, iv.length);
			cipher.doFinal(ByteBuffer.wrap(plainBytes),
					ByteBuffer.wrap(encryptedBytes, iv.length, encryptedBytes.length - iv.length));

			return Base64.getUrlEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException("加密失败", e);
		}
	}

	public String decrypt(String base64Ciphertext) {
		try {
			SecretKey key = initKey();

			byte[] encryptedBytes = Base64.getUrlDecoder().decode(base64Ciphertext);

			ByteBuffer buffer = ByteBuffer.wrap(encryptedBytes);
			byte[] iv = new byte[IV_LENGTH_BYTE];
			buffer.get(iv);

			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			byte[] plainBytes = cipher.doFinal(encryptedBytes, iv.length, encryptedBytes.length - iv.length);
			return new String(plainBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("解密失败", e);
		}
	}

}