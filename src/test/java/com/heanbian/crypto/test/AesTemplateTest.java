package com.heanbian.crypto.test;

import com.heanbian.crypto.AesTemplate;

public class AesTemplateTest {

	public static void main(String[] args) {
		AesTemplate aes = new AesTemplate();

		// 加密
		String ciphertext = aes.encrypt("hello world");
		System.out.println("Encrypted: " + ciphertext);

		// 解密
		String plaintext = aes.decrypt(ciphertext);
		// 输出 hello world
		System.out.println("Decrypted: " + plaintext);
	}

}
