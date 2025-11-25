package com.heanbian.block.crypto;

import module java.base;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class EcTemplate {

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static final String ALGORITHM = "EC";
	private static final String STANDARD_CURVE_NAME = "secp256r1"; // NIST P-256曲线标准名称
	private static final String TRANSFORMATION = "ECIES"; // 加密方案

	private final PublicKey publicKey;
	private final PrivateKey privateKey;

	public EcTemplate() {
		KeyPair keyPair = generateKeyPair(STANDARD_CURVE_NAME);
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	public EcTemplate(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = validateKey(publicKey, PublicKey.class);
		this.privateKey = validateKey(privateKey, PrivateKey.class);
	}

	private KeyPair generateKeyPair(String curveName) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
			ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
			generator.initialize(ecSpec, new SecureRandom());
			return generator.generateKeyPair();
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new RuntimeException("密钥对生成失败", e);
		}
	}

	public String encrypt(String plaintext) {
		validateInput(plaintext, "加密内容");
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().encodeToString(cipherText);
		} catch (Exception e) {
			throw new RuntimeException("加密失败", e);
		}
	}

	public String decrypt(String ciphertext) {
		validateInput(ciphertext, "密文");
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION, BouncyCastleProvider.PROVIDER_NAME);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decoded = Base64.getUrlDecoder().decode(ciphertext);
			byte[] decrypted = cipher.doFinal(decoded);
			return new String(decrypted, StandardCharsets.UTF_8);
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

	public static PublicKey deserializePublicKey(String base64Key) {
		return (PublicKey) deserializeKey(base64Key, X509EncodedKeySpec.class, PublicKey.class);
	}

	public static PrivateKey deserializePrivateKey(String base64Key) {
		return (PrivateKey) deserializeKey(base64Key, PKCS8EncodedKeySpec.class, PrivateKey.class);
	}

	private static Key deserializeKey(String base64Key, Class<? extends KeySpec> keySpecType,
			Class<? extends Key> keyType) {
		validateInput(base64Key, "Base64密钥字符串");
		try {
			byte[] encoded = Base64.getUrlDecoder().decode(base64Key);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);

			KeySpec spec = keySpecType == X509EncodedKeySpec.class ? //
					new X509EncodedKeySpec(encoded)//
					: new PKCS8EncodedKeySpec(encoded);

			return keyType == PublicKey.class ? factory.generatePublic(spec) : factory.generatePrivate(spec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new RuntimeException("密钥反序列化失败", e);
		}
	}

	private static void validateInput(String input, String paramName) {
		if (input == null || input.isEmpty()) {
			throw new IllegalArgumentException(paramName + "不能为空");
		}
	}

	private <T extends Key> T validateKey(T key, Class<T> keyType) {
		if (key == null) {
			throw new IllegalArgumentException(keyType.getSimpleName() + "不能为空");
		}
		if (!key.getAlgorithm().equals(ALGORITHM)) {
			throw new IllegalArgumentException("不支持的密钥算法类型");
		}
		return key;
	}

}