package com.heanbian.block.crypto.test;

import com.heanbian.block.crypto.EcTemplate;

public class EcTemplateTest {
	
	public static void main(String[] args) {
		EcTemplate ec = new EcTemplate();

		// 加密
		String ciphertext = ec.encrypt("hello world");
		System.out.println("Encrypted: " + ciphertext);

		// 解密
		String plaintext = ec.decrypt(ciphertext);
		System.out.println("Decrypted: " + plaintext); // 输出 hello world
	}

}
