package com.heanbian.block.crypto;

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RsaTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	static final String ALG = "RSA";
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public RsaTemplate() {
		KeyPair keyPair = getKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	KeyPair getKeyPair() {
		KeyPairGenerator k;
		try {
			k = KeyPairGenerator.getInstance(ALG);
			k.initialize(2048);
			return k.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public String encrypt(String content) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
			byte[] encoded = cipher.doFinal(content.getBytes(Charset.defaultCharset()));
			return Base64.getEncoder().encodeToString(encoded);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String content) {
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALG);
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] decoded = cipher.doFinal(Base64.getDecoder().decode(content));
			return new String(decoded, Charset.defaultCharset());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}