package com.heanbian.block.reactive.crypto;

import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * 加密解密简单模板类
 * 
 * @author Heanbian
 * @version 1.0
 */
public final class SimpleCryptTemplate {

	/**
	 * 算法
	 */
	private static final String ALGORITHM = "AES";

	/**
	 * 默认密钥
	 */
	private static final String DEFAULT_KEY = "gfdertfghjkuyrtg";

	/**
	 * 填充方式
	 */
	private static final String TRANSFORMATION = "AES/ECB/NoPadding";

	private SimpleCryptTemplate() {}

	/**
	 * 加密，使用默认密钥{@link #DEFAULT_KEY}
	 * 
	 * @param plaintext 明文
	 * @return 密文
	 */
	public static String encrypt(String plaintext) {
		return encrypt(plaintext, DEFAULT_KEY);
	}

	/**
	 * 解密，使用默认密钥{@link #DEFAULT_KEY}
	 * 
	 * @param ciphertext 密文
	 * @return 明文
	 */
	public static String decrypt(String ciphertext) {
		return decrypt(ciphertext, DEFAULT_KEY);
	}

	/**
	 * 加密
	 * 
	 * @param plaintext 明文
	 * @param key       密钥
	 * @return 密文
	 */
	public static String encrypt(String plaintext, String key) {
		Objects.requireNonNull(plaintext, "plaintext must not be null");
		Objects.requireNonNull(key, "key must not be null");
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			int blockSize = cipher.getBlockSize();
			byte[] buf = plaintext.getBytes();
			int length = buf.length;
			if (length % blockSize != 0) {
				length = length + (blockSize - (length % blockSize));
			}
			byte[] _plaintext = new byte[length];
			System.arraycopy(buf, 0, _plaintext, 0, buf.length);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), ALGORITHM));
			return parseByteToHexString(cipher.doFinal(_plaintext));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 解密
	 * 
	 * @param ciphertext 密文
	 * @param key        密钥
	 * @return 明文
	 */
	public static String decrypt(String ciphertext, String key) {
		Objects.requireNonNull(ciphertext, "ciphertext must not be null");
		Objects.requireNonNull(key, "key must not be null");
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), ALGORITHM));
			return new String(cipher.doFinal(parseHexStringToByte(ciphertext)));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static String parseByteToHexString(byte[] buf) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; ++i) {
			String hex = Integer.toHexString(buf[i] & 255);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	private static byte[] parseHexStringToByte(String hex) {
		if (hex.length() < 1) {
			return new byte[0];
		}
		int len = hex.length() / 2;
		byte[] rs = new byte[len];
		for (int i = 0; i < len; ++i) {
			int high = Integer.parseInt(hex.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hex.substring(i * 2 + 1, i * 2 + 2), 16);
			rs[i] = (byte) (high * 16 + low);
		}
		return rs;
	}

}
