package com.heanbian.block.crypto;

public final class AesTemplate {

	private final LargeAesTemplate largeAesTemplate;

	public AesTemplate() {
		this.largeAesTemplate = new LargeAesTemplate();
	}

	public AesTemplate(String base64Key) {
		this.largeAesTemplate = new LargeAesTemplate(base64Key);
	}

	public String encrypt(String plaintext) {
		return largeAesTemplate.encrypt(plaintext);
	}

	public String decrypt(String ciphertext) {
		return largeAesTemplate.decrypt(ciphertext);
	}

}