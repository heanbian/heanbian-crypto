package com.heanbian.block.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AesTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String DEFAULT_ALGORITHM = "AES";
	private static final String DEFAULT_PADDING = "AES/CBC/PKCS7Padding";
	private static final int KEY_LENGTH_BYTES = 16; // AES-128 requires a 16-byte key
	private static final int IV_LENGTH_BYTES = 16; // CBC mode requires a 16-byte IV

	private final String padding;
	private final SecretKeySpec secretKeySpec;
	private final IvParameterSpec ivParameterSpec;

	public AesTemplate() {
		this(DEFAULT_ALGORITHM, "1234567890abcdef", "1234567890abcdef", DEFAULT_PADDING);
	}

	public AesTemplate(String alg, String key, String iv, String pad) {
		if (key == null || key.getBytes(StandardCharsets.UTF_8).length != KEY_LENGTH_BYTES) {
			throw new IllegalArgumentException("Key must be 16 bytes for AES-128");
		}
		if (iv == null || iv.getBytes(StandardCharsets.UTF_8).length != IV_LENGTH_BYTES) {
			throw new IllegalArgumentException("IV must be 16 bytes for AES-CBC");
		}

		this.padding = pad;
		this.secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), alg);
		this.ivParameterSpec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
	}

	public String encrypt(String text) {
		try {
			Cipher cipher = Cipher.getInstance(padding);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException("Encryption failed", e);
		}
	}

	public String decrypt(String encryptedText) {
		try {
			Cipher cipher = Cipher.getInstance(padding);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedText));
			return new String(decryptedBytes, StandardCharsets.UTF_8).strip();
		} catch (Exception e) {
			throw new RuntimeException("Decryption failed", e);
		}
	}

}