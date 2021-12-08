package com.heanbian.block.crypto;

import java.nio.charset.Charset;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.UrlBase64;

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
		return decrypt(UrlBase64.decode(text), this.key.getBytes(), this.iv.getBytes());
	}

	String encrypt(byte[] text, byte[] key, byte[] iv) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(this.pad);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, this.alg), new IvParameterSpec(iv));
			return new String(UrlBase64.encode(cipher.doFinal(text)), Charset.defaultCharset());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	String decrypt(byte[] text, byte[] key, byte[] iv) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(this.pad);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, this.alg), new IvParameterSpec(iv));
			return new String(cipher.doFinal(text), Charset.defaultCharset()).strip();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
