package com.heanbian.crypto;

import javax.crypto.SecretKey;

/**
 * 兼容旧API的包装类。
 * 建议新代码优先直接使用 AesTemplate。
 */
public final class LargeAesTemplate {

	private final AesTemplate delegate;

	public LargeAesTemplate() {
		this.delegate = new AesTemplate();
	}

	public LargeAesTemplate(String base64Key) {
		this.delegate = new AesTemplate(base64Key);
	}

	public SecretKey initKey() {
		return delegate.secretKey();
	}

	public String generateKey() {
		return AesTemplate.generateKey();
	}

	public String getKeyString() {
		return delegate.getKeyString();
	}

	public String encrypt(String plaintext) {
		return delegate.encrypt(plaintext);
	}

	public String decrypt(String ciphertext) {
		return delegate.decrypt(ciphertext);
	}

}
