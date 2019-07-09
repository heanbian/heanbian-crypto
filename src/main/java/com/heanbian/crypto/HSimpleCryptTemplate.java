package com.heanbian.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class HSimpleCryptTemplate {

	private static final String ALGORITHM = "AES";

	private static final String DEFAULT_KEY = "gfdertfghjkuyrtg";

	private static final String TRANSFORMATION = "AES/ECB/NoPadding";

	private HSimpleCryptTemplate() {
	}

	public static String encrypt(String data) throws Exception {
		return encrypt(data, DEFAULT_KEY);
	}

	public static String decrypt(String data) throws Exception {
		return decrypt(data, DEFAULT_KEY);
	}

	public static String encrypt(String data, String key) throws Exception {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		int blockSize = cipher.getBlockSize();
		byte[] dataBytes = data.getBytes();
		int length = dataBytes.length;
		if (length % blockSize != 0) {
			length = length + (blockSize - (length % blockSize));
		}
		byte[] plaintext = new byte[length];
		System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getBytes(), ALGORITHM));
		return parseByteToHexString(cipher.doFinal(plaintext));
	}

	public static String decrypt(String data, String key) throws Exception {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes(), ALGORITHM));
		return new String(cipher.doFinal(parseHexStringToByte(data)));
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
