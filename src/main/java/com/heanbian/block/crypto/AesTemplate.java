package com.heanbian.block.crypto;

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

	private String alg;
	private String iv;
	private String key;
	private String pad;

	public AesTemplate() {
		this("AES", "1234567890abcdef", "1234567890abcdef", "AES/CBC/PKCS7Padding");
	}

	public AesTemplate(String alg, String iv, String key, String pad) {
		this.alg = alg;
		this.iv = iv;
		this.key = key;
		this.pad = pad;
	}

	public String encrypt(String text) {
		return encrypt(text.getBytes(), this.key.getBytes(), this.iv.getBytes());
	}

	public String decrypt(String text) {
		return decrypt(Base64.getDecoder().decode(text), this.key.getBytes(), this.iv.getBytes());
	}

	String encrypt(byte[] text, byte[] key, byte[] iv) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(this.pad);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, this.alg), new IvParameterSpec(iv));
			return Base64.getEncoder().encodeToString(cipher.doFinal(text));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	String decrypt(byte[] text, byte[] key, byte[] iv) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(this.pad);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, this.alg), new IvParameterSpec(iv));
			return new String(cipher.doFinal(text));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
