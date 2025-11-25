package com.heanbian.block.crypto;

import module java.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class RsaTemplate {

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static final String ALGORITHM = "RSA";
	private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	private PublicKey publicKey;
	private PrivateKey privateKey;

	public RsaTemplate() {
		KeyPair keyPair = generateKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	private KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
			generator.initialize(2048); // 使用 2048 位密钥长度
			return generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("无法生成 RSA 密钥对", e);
		}
	}

	public String encrypt(String content) {
		validate(content, "加密内容不能为空");
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedBytes = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException("加密失败", e);
		}
	}

	public String decrypt(String encryptedContent) {
		validate(encryptedContent, "解密内容不能为空");
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedContent));
			return new String(decryptedBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("解密失败", e);
		}
	}

	public String getPublicKeyString() {
		return Base64.getUrlEncoder().encodeToString(publicKey.getEncoded());
	}

	public String getPrivateKeyString() {
		return Base64.getUrlEncoder().encodeToString(privateKey.getEncoded());
	}

	public PublicKey loadPublicKey(String publicKeyString) {
		validate(publicKeyString, "无效的公钥字符串");
		try {
			byte[] encodedKey = Base64.getUrlDecoder().decode(publicKeyString);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
			return factory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new IllegalArgumentException("加载公钥失败", e);
		}
	}

	public PrivateKey loadPrivateKey(String privateKeyString) {
		validate(privateKeyString, "无效的私钥字符串");
		try {
			byte[] encodedKey = Base64.getUrlDecoder().decode(privateKeyString);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
			return factory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new IllegalArgumentException("加载私钥失败", e);
		}
	}

	private void validate(String input, String errorMessage) {
		if (input == null || input.trim().isEmpty()) {
			throw new IllegalArgumentException(errorMessage);
		}
	}

}