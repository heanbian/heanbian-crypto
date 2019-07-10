package com.heanbian.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 加密解密模板类
 * 
 * @author 河岸边
 * @since 1.0
 * @version 1.0
 */
public final class HCryptTemplate {

	/**
	 * 算法：AES
	 */
	private static final String ALGORITHM = "AES";

	/**
	 * 默认向量
	 */
	private static final String DEFAULT_IV = "1234567890abcdef";

	/**
	 * 默认密钥
	 */
	private static final String DEFAULT_KEY = "1234567890abcdef";

	/**
	 * 填充方式
	 */
	private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

	private HCryptTemplate() {
	}

	/**
	 * 加密，使用默认{@link #DEFAULT_KEY}
	 * 
	 * @param plaintext 明文
	 * @return 密文
	 */
	public static String encrypt(String plaintext) {
		return encrypt(plaintext, DEFAULT_KEY);
	}

	/**
	 * 加密
	 * 
	 * @param plaintext 明文
	 * @param secretKey 密钥，长度16位
	 * @return 密文
	 */
	public static String encrypt(String plaintext, String secretKey) {
		return encrypt(plaintext, secretKey, DEFAULT_IV);
	}

	/**
	 * 加密
	 * 
	 * @param plaintext 明文
	 * @param secretKey 密钥，长度16位
	 * @param iv        向量，长度16位
	 * @return 密文
	 */
	public static String encrypt(String plaintext, String secretKey, String iv) {
		Objects.requireNonNull(plaintext, "plaintext must not be null");
		Objects.requireNonNull(secretKey, "secretKey must not be null");
		Objects.requireNonNull(iv, "iv must not be null");

		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), ALGORITHM),
					new IvParameterSpec(iv.getBytes()));
			return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 解密，使用默认{@link #DEFAULT_KEY}
	 * 
	 * @param ciphertext 密文
	 * @return 明文
	 */
	public static String decrypt(String ciphertext) {
		return decrypt(ciphertext, DEFAULT_KEY);
	}

	/**
	 * 解密
	 * 
	 * @param ciphertext 密文
	 * @param secretKey  密钥，长度16位
	 * @return 明文
	 */
	public static String decrypt(String ciphertext, String secretKey) {
		return decrypt(ciphertext, secretKey, DEFAULT_IV);
	}

	/**
	 * 解密
	 * 
	 * @param ciphertext 密文
	 * @param secretKey  密钥，长度16位
	 * @param iv         向量，长度16位
	 * @return 明文
	 */
	public static String decrypt(String ciphertext, String secretKey, String iv) {
		Objects.requireNonNull(ciphertext, "ciphertext must not be null");
		Objects.requireNonNull(secretKey, "secretKey must not be null");
		Objects.requireNonNull(iv, "iv must not be null");

		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), ALGORITHM),
					new IvParameterSpec(iv.getBytes()));
			return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext.replaceAll(" ", "+"))),
					StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
