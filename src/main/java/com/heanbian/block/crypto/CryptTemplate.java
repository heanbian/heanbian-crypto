package com.heanbian.block.crypto;

import static java.util.Objects.requireNonNull;

import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 加密解密模板类
 * 
 * @author Heanbian
 */
public final class CryptTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private CryptTemplate() {
	}

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
	private static final String TRANSFORMATION = "AES/CBC/PKCS7Padding";

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
		requireNonNull(plaintext, "plaintext must not be null");
		requireNonNull(secretKey, "secretKey must not be null");
		requireNonNull(iv, "iv must not be null");

		return encrypt(plaintext.getBytes(), secretKey.getBytes(), iv.getBytes());
	}

	/**
	 * 加密
	 * 
	 * @param plaintext 明文
	 * @param secretKey 密钥，长度16位
	 * @param iv        向量，长度16位
	 * @return 密文
	 */
	public static String encrypt(byte[] plaintext, byte[] secretKey, byte[] iv) {
		requireNonNull(plaintext, "plaintext must not be null");
		requireNonNull(secretKey, "secretKey must not be null");
		requireNonNull(iv, "iv must not be null");

		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, ALGORITHM), new IvParameterSpec(iv));
			return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
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
		requireNonNull(ciphertext, "ciphertext must not be null");
		requireNonNull(secretKey, "secretKey must not be null");
		requireNonNull(iv, "iv must not be null");

		return decrypt(Base64.getDecoder().decode(ciphertext), secretKey.getBytes(), iv.getBytes());
	}

	/**
	 * 解密
	 * 
	 * @param ciphertext 密文
	 * @param secretKey  密钥，长度16位
	 * @param iv         向量，长度16位
	 * @return 明文
	 */
	public static String decrypt(byte[] ciphertext, byte[] secretKey, byte[] iv) {
		requireNonNull(ciphertext, "ciphertext must not be null");
		requireNonNull(secretKey, "secretKey must not be null");
		requireNonNull(iv, "iv must not be null");

		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, ALGORITHM), new IvParameterSpec(iv));
			return new String(cipher.doFinal(ciphertext));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
