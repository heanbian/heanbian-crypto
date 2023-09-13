package com.heanbian.block.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SM4Template {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static final String DEFAULT_KEY = "0123456789abcdef";

	public String encrypt(String plainText) {
		return encrypt(plainText, DEFAULT_KEY);
	}

	public String encrypt(String plainText, String key) {
		try {
			Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding");
			SecretKeySpec sm4Key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "SM4");
			cipher.init(Cipher.ENCRYPT_MODE, sm4Key, new IvParameterSpec(new byte[16]));
			byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(cipherText);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String encryptedText) {
		return decrypt(encryptedText, DEFAULT_KEY);
	}

	public String decrypt(String encryptedText, String key) {
		try {
			Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding");
			SecretKeySpec sm4Key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "SM4");
			cipher.init(Cipher.DECRYPT_MODE, sm4Key, new IvParameterSpec(new byte[16]));
			byte[] decodedCipherText = Base64.getDecoder().decode(encryptedText);
			byte[] decryptedText = cipher.doFinal(decodedCipherText);
			return new String(decryptedText, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}