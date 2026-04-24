package com.heanbian.crypto;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

final class CryptoSupport {

	static final String BOUNCY_CASTLE = BouncyCastleProvider.PROVIDER_NAME;

	private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder();
	private static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	static {
		ensureBouncyCastle();
	}

	private CryptoSupport() {
	}

	static void ensureBouncyCastle() {
		if (Security.getProvider(BOUNCY_CASTLE) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	static SecureRandom secureRandom() {
		return SECURE_RANDOM;
	}

	static String encodeBase64(byte[] bytes) {
		return BASE64_ENCODER.encodeToString(bytes);
	}

	static byte[] decodeBase64(String value, String name) {
		try {
			return BASE64_DECODER.decode(requireText(value, name));
		} catch (IllegalArgumentException ex) {
			throw new IllegalArgumentException(name + "不是有效的 Base64Url 字符串", ex);
		}
	}

	static String requireText(String value, String name) {
		if (value == null || value.trim().isEmpty()) {
			throw new IllegalArgumentException(name + "不能为空");
		}
		return value.trim();
	}

	static void requireAnyLength(byte[] bytes, String name, int... validLengths) {
		for (int validLength : validLengths) {
			if (bytes.length == validLength) {
				return;
			}
		}
		throw new IllegalArgumentException(
				name + "长度无效，期望 " + Arrays.toString(validLengths) + " 字节，实际 " + bytes.length + " 字节");
	}

	static void requireAtLeast(byte[] bytes, String name, int minLength) {
		if (bytes.length < minLength) {
			throw new IllegalArgumentException(name + "长度无效，至少 " + minLength + " 字节，实际 " + bytes.length + " 字节");
		}
	}

}
