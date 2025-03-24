package com.heanbian.block.crypto.test;

import com.heanbian.block.crypto.LargeAesTemplate;

public class LargeAesTemplateTest {
	
	public static void main(String[] args) {
		LargeAesTemplate aes = new LargeAesTemplate();

		// 加密
		String ciphertext = aes.encrypt("hello world");
		System.out.println("Encrypted: " + ciphertext);

		// 解密
		String plaintext = aes.decrypt(ciphertext);
		System.out.println("Decrypted: " + plaintext); // 输出 hello world
	}

}
