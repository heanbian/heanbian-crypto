package com.heanbian.block.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SM4Template {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static final String DEFAULT_KEY = "0123456789abcdef";

	public String encrypt(String plainText) {
		return encrypt(plainText, DEFAULT_KEY);
	}

	public String encrypt(String plainText, String key) {
		try {
			byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
			byte[] plaintextBytes = plainText.getBytes(StandardCharsets.UTF_8);

			SM4Engine engine = new SM4Engine();
			CBCBlockCipher cipher = (CBCBlockCipher) CBCBlockCipher.newInstance(engine);
			BufferedBlockCipher pCipher = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
			pCipher.init(true, new KeyParameter(keyBytes));

			byte[] encryptedBytes = new byte[pCipher.getOutputSize(plaintextBytes.length)];
			int outputLen = pCipher.processBytes(plaintextBytes, 0, plaintextBytes.length, encryptedBytes, 0);
			pCipher.doFinal(encryptedBytes, outputLen);

			return Base64.getEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String encryptedText) {
		return decrypt(encryptedText, DEFAULT_KEY);
	}

	public String decrypt(String encryptedText, String key) {
		try {
			byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
			byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);

			SM4Engine engine = new SM4Engine();
			CBCBlockCipher cipher = (CBCBlockCipher) CBCBlockCipher.newInstance(engine);
			BufferedBlockCipher pCipher = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
			pCipher.init(false, new KeyParameter(keyBytes));

			byte[] decryptedBytes = new byte[pCipher.getOutputSize(encryptedBytes.length)];
			int outputLen = pCipher.processBytes(encryptedBytes, 0, encryptedBytes.length, decryptedBytes, 0);
			pCipher.doFinal(decryptedBytes, outputLen);

			return new String(decryptedBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}