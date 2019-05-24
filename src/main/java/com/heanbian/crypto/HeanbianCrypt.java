package com.heanbian.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 加密解密类
 * 
 * @author heanbian@heanbian.com
 * @since 1.0
 * @version 1.0
 */
public enum HeanbianCrypt {

	INSTANCE;

	/**
	 * 算法：AES
	 */
	private final String ALGORITHM = "AES";

	/**
	 * 向量：1234567890abcdef
	 */
	private final String DEFAULT_IV = "1234567890abcdef";

	/**
	 * 默认密钥：1234567890abcdef
	 */
	private final String DEFAULT_KEY = "1234567890abcdef";

	/**
	 * AES/CBC/PKCS5Padding
	 */
	private final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

	private HeanbianCrypt() {
	}

	/**
	 * 加密，使用默认{@link #DEFAULT_KEY}
	 * 
	 * @param plaintext 明文
	 * @return 密文
	 * @throws Exception 异常
	 */
	public String encrypt(String plaintext) throws Exception {
		return encrypt(plaintext, DEFAULT_KEY);
	}

	/**
	 * 加密
	 * 
	 * @param plaintext 明文
	 * @param secretKey 密钥，长度16位
	 * @return 密文
	 * @throws Exception 异常
	 */
	public String encrypt(String plaintext, String secretKey) throws Exception {
		return encrypt(plaintext, secretKey, DEFAULT_IV);
	}

	/**
	 * 加密
	 * 
	 * @param plaintext 明文
	 * @param secretKey 密钥，长度16位
	 * @param iv        向量，长度16位
	 * @return 密文
	 * @throws Exception 异常
	 */
	public String encrypt(String plaintext, String secretKey, String iv) throws Exception {
		String opt = Optional.ofNullable(plaintext).orElse("");
		String key = Optional.ofNullable(secretKey).orElse(DEFAULT_KEY);
		String _iv = Optional.ofNullable(iv).orElse(DEFAULT_IV);
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM),
				new IvParameterSpec(_iv.getBytes()));
		return Base64.getEncoder().encodeToString(cipher.doFinal(opt.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * 解密，使用默认{@link #DEFAULT_KEY}
	 * 
	 * @param ciphertext 密文
	 * @return 明文
	 * @throws Exception 异常
	 */
	public String decrypt(String ciphertext) throws Exception {
		return decrypt(ciphertext, DEFAULT_KEY);
	}

	/**
	 * 解密
	 * 
	 * @param ciphertext 密文
	 * @param secretKey  密钥，长度16位
	 * @return 明文
	 * @throws Exception 异常
	 */
	public String decrypt(String ciphertext, String secretKey) throws Exception {
		return decrypt(ciphertext, secretKey, DEFAULT_IV);
	}

	/**
	 * 解密
	 * 
	 * @param ciphertext 密文
	 * @param secretKey  密钥，长度16位
	 * @param iv         向量，长度16位
	 * @return 明文
	 * @throws Exception 异常
	 */
	public String decrypt(String ciphertext, String secretKey, String iv) throws Exception {
		String opt = Optional.ofNullable(ciphertext).orElse("");
		opt = opt.replaceAll(" ", "+");
		String key = Optional.ofNullable(secretKey).orElse(DEFAULT_KEY);
		String _iv = Optional.ofNullable(iv).orElse(DEFAULT_IV);
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM),
				new IvParameterSpec(_iv.getBytes()));
		return new String(cipher.doFinal(Base64.getDecoder().decode(opt)), StandardCharsets.UTF_8);
	}

}
