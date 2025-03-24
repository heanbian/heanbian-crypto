package com.heanbian.block.crypto.test;

import com.heanbian.block.crypto.AesTemplate;

public class AesTemplateTest {
	
	public static void main(String[] args) {
		AesTemplate aes = new AesTemplate();

		// 加密
		String ciphertext = aes.encrypt("hello world");
		System.out.println("Encrypted: " + ciphertext);

		// 解密
		String plaintext = aes.decrypt(ciphertext);
		System.out.println("Decrypted: " + plaintext); // 输出 hello world
	}

}
