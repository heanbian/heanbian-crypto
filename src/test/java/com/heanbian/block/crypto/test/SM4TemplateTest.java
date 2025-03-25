package com.heanbian.block.crypto.test;

import com.heanbian.block.crypto.SM4Template;

public class SM4TemplateTest {

	public static void main(String[] args) {
		SM4Template sm4 = new SM4Template();

		// 加密
		String ciphertext = sm4.encrypt("hello world");
		System.out.println("Encrypted: " + ciphertext);

		// 解密
		String plaintext = sm4.decrypt(ciphertext);
		// 输出 hello world
		System.out.println("Decrypted: " + plaintext); 
	}

}
