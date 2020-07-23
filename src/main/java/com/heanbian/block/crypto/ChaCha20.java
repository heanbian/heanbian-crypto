package com.heanbian.block.crypto;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

/**
 * ChaCha20加解密
 * 
 * @author 马洪
 */
public class ChaCha20 {

	private final String chacha20;
	private final SecretKey key;

	public ChaCha20() {
		this.chacha20 = "ChaCha20";
		this.key = this.getKey();
	}

	/**
	 * 加密
	 * 
	 * @param text    明文
	 * @param nonce   12位
	 * @param counter
	 * @return encrypted
	 */
	public byte[] encrypt(byte[] text, byte[] nonce, int counter) {
		try {
			Cipher cipher = Cipher.getInstance(this.chacha20);
			ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
			cipher.init(Cipher.ENCRYPT_MODE, this.key, param);
			return cipher.doFinal(text);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * 解密
	 * 
	 * @param text    密文
	 * @param nonce   12位
	 * @param counter
	 * @return decrypted
	 */
	public byte[] decrypt(byte[] text, byte[] nonce, int counter) {
		try {
			Cipher cipher = Cipher.getInstance(this.chacha20);
			ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, counter);
			cipher.init(Cipher.DECRYPT_MODE, this.key, param);
			return cipher.doFinal(text);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private SecretKey getKey() {
		try {
			KeyGenerator gen = KeyGenerator.getInstance(this.chacha20);
			gen.init(256, SecureRandom.getInstanceStrong());
			return gen.generateKey();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * hex
	 * 
	 * @param buf
	 * @return result
	 */
	public String toHex(byte[] buf) {
		StringBuilder result = new StringBuilder();
		for (byte temp : buf) {
			result.append(String.format("%02x", temp));
		}
		return result.toString();
	}

}
