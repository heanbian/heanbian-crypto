package com.heanbian.crypto.test;

import com.heanbian.crypto.RsaTemplate;

public class RsaTemplateTest {

	public static void main(String[] args) {
		RsaTemplate rsa = new RsaTemplate();

		// 加密
		String ciphertext = rsa.encrypt("hello world");
		System.out.println("Encrypted: " + ciphertext);

		// 解密
		String plaintext = rsa.decrypt(ciphertext);
		// 输出 hello world
		System.out.println("Decrypted: " + plaintext); 
	}

}
