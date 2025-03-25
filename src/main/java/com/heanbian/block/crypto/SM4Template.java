package com.heanbian.block.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SM4Template {

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public static final String DEFAULT_KEY = "0123456789abcdef";
	private static final String ALGORITHM = "SM4/CBC/PKCS7Padding";
	private static final int IV_SIZE = 16;
	private static final int KEY_SIZE = 16;

	public String encrypt(String plainText) {
		return encrypt(plainText, DEFAULT_KEY);
	}

	public String encrypt(String plainText, String key) {
		try {
			SecretKeySpec sm4Key = generateKeySpec(key);

			Cipher cipher = Cipher.getInstance(ALGORITHM);
			IvParameterSpec iv = generateIv();
			cipher.init(Cipher.ENCRYPT_MODE, sm4Key, iv);

			byte[] encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			byte[] combined = combineIvAndData(iv.getIV(), encryptedData);

			return Base64.getUrlEncoder().encodeToString(combined);
		} catch (Exception e) {
			throw new RuntimeException("加密失败", e);
		}
	}

	public String decrypt(String encryptedText) {
		return decrypt(encryptedText, DEFAULT_KEY);
	}

	public String decrypt(String encryptedText, String key) {
		try {
			SecretKeySpec sm4Key = generateKeySpec(key);

			byte[] combined = Base64.getUrlDecoder().decode(encryptedText);
			byte[][] ivAndData = splitIvAndData(combined);

			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, sm4Key, new IvParameterSpec(ivAndData[0]));

			byte[] decryptedText = cipher.doFinal(ivAndData[1]);
			return new String(decryptedText, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("解密失败", e);
		}
	}

	private SecretKeySpec generateKeySpec(String key) {
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		if (keyBytes.length != KEY_SIZE) {
			throw new IllegalArgumentException("无效数据");
		}
		return new SecretKeySpec(keyBytes, "SM4");
	}

	private IvParameterSpec generateIv() {
		byte[] iv = new byte[IV_SIZE];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	private byte[] combineIvAndData(byte[] iv, byte[] data) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			out.write(iv);
			out.write(data);
			return out.toByteArray();
		}
	}

	private byte[][] splitIvAndData(byte[] combined) {
		if (combined.length < IV_SIZE) {
			throw new IllegalArgumentException("无效数据");
		}
		return new byte[][] { //
				Arrays.copyOfRange(combined, 0, IV_SIZE), //
				Arrays.copyOfRange(combined, IV_SIZE, combined.length) };
	}

}