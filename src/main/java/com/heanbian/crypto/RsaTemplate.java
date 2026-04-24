package com.heanbian.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public final class RsaTemplate {

	private static final String KEY_ALGORITHM = "RSA";
	private static final String WRAP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	private static final String DATA_CIPHER = "AES/GCM/NoPadding";

	private static final int RSA_KEY_SIZE = 2048;
	private static final int AES_KEY_SIZE = 256;
	private static final int GCM_IV_LENGTH = 12;
	private static final int GCM_TAG_LENGTH_BIT = 128;

	private static final OAEPParameterSpec OAEP_SPEC = new OAEPParameterSpec(
			"SHA-256",
			"MGF1",
			MGF1ParameterSpec.SHA256,
			PSource.PSpecified.DEFAULT);

	private final PublicKey publicKey;
	private final PrivateKey privateKey;

	public RsaTemplate() {
		this(generateKeyPair());
	}

	public RsaTemplate(PublicKey publicKey) {
		this(publicKey, null);
	}

	public RsaTemplate(PublicKey publicKey, PrivateKey privateKey) {
		if (publicKey == null && privateKey == null) {
			throw new IllegalArgumentException("publicKey 和 privateKey 不能同时为空");
		}
		this.publicKey = publicKey == null ? null : validatePublicKey(publicKey);
		this.privateKey = privateKey == null ? null : validatePrivateKey(privateKey);
	}

	public RsaTemplate(String publicKeyString, String privateKeyString) {
		this(
				publicKeyString == null || publicKeyString.isBlank() ? null : deserializePublicKey(publicKeyString),
				privateKeyString == null || privateKeyString.isBlank() ? null : deserializePrivateKey(privateKeyString));
	}

	private RsaTemplate(KeyPair keyPair) {
		this(keyPair.getPublic(), keyPair.getPrivate());
	}

	public String encrypt(String plaintext) {
		Objects.requireNonNull(plaintext, "plaintext不能为空");
		if (publicKey == null) {
			throw new IllegalStateException("当前实例不包含公钥，无法加密");
		}
		try {
			SecretKey aesKey = generateAesKey();

			byte[] iv = new byte[GCM_IV_LENGTH];
			CryptoSupport.secureRandom().nextBytes(iv);

			byte[] encryptedContent = encryptData(plaintext.getBytes(StandardCharsets.UTF_8), aesKey, iv);
			byte[] wrappedAesKey = rsaEncrypt(aesKey.getEncoded(), publicKey);

			ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + wrappedAesKey.length + iv.length + encryptedContent.length);
			buffer.putInt(wrappedAesKey.length);
			buffer.put((byte) iv.length);
			buffer.put(wrappedAesKey);
			buffer.put(iv);
			buffer.put(encryptedContent);

			return CryptoSupport.encodeBase64(buffer.array());
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("RSA混合加密失败", ex);
		}
	}

	public String decrypt(String ciphertext) {
		if (privateKey == null) {
			throw new IllegalStateException("当前实例不包含私钥，无法解密");
		}
		try {
			byte[] payload = CryptoSupport.decodeBase64(ciphertext, "RSA密文");
			ByteBuffer buffer = ByteBuffer.wrap(payload);

			if (buffer.remaining() < 5) {
				throw new IllegalArgumentException("RSA密文格式不合法");
			}

			int wrappedKeyLength = buffer.getInt();
			int ivLength = Byte.toUnsignedInt(buffer.get());

			if (wrappedKeyLength <= 0 || ivLength <= 0 || buffer.remaining() < wrappedKeyLength + ivLength + 16) {
				throw new IllegalArgumentException("RSA密文格式不完整");
			}

			byte[] wrappedKey = new byte[wrappedKeyLength];
			buffer.get(wrappedKey);

			byte[] iv = new byte[ivLength];
			buffer.get(iv);

			byte[] encryptedContent = new byte[buffer.remaining()];
			buffer.get(encryptedContent);

			byte[] aesKeyBytes = rsaDecrypt(wrappedKey, privateKey);
			CryptoSupport.requireAnyLength(aesKeyBytes, "解包后的AES密钥", 16, 24, 32);

			SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
			byte[] plain = decryptData(encryptedContent, aesKey, iv);

			return new String(plain, StandardCharsets.UTF_8);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("RSA混合解密失败", ex);
		}
	}

	public String getPublicKeyString() {
		if (publicKey == null) {
			throw new IllegalStateException("当前实例不包含公钥");
		}
		return CryptoSupport.encodeBase64(publicKey.getEncoded());
	}

	public String getPrivateKeyString() {
		if (privateKey == null) {
			throw new IllegalStateException("当前实例不包含私钥");
		}
		return CryptoSupport.encodeBase64(privateKey.getEncoded());
	}

	public static PublicKey deserializePublicKey(String publicKeyString) {
		try {
			byte[] encodedKey = CryptoSupport.decodeBase64(publicKeyString, "RSA公钥");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			return java.security.KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(keySpec);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("RSA公钥反序列化失败", ex);
		}
	}

	public static PrivateKey deserializePrivateKey(String privateKeyString) {
		try {
			byte[] encodedKey = CryptoSupport.decodeBase64(privateKeyString, "RSA私钥");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			return java.security.KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(keySpec);
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("RSA私钥反序列化失败", ex);
		}
	}

	/**
	 * 兼容旧API：仅返回解析结果，不修改当前实例状态。
	 */
	public PublicKey loadPublicKey(String publicKeyString) {
		return deserializePublicKey(publicKeyString);
	}

	/**
	 * 兼容旧API：仅返回解析结果，不修改当前实例状态。
	 */
	public PrivateKey loadPrivateKey(String privateKeyString) {
		return deserializePrivateKey(privateKeyString);
	}

	private static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			generator.initialize(RSA_KEY_SIZE);
			return generator.generateKeyPair();
		} catch (GeneralSecurityException ex) {
			throw new CryptoException("RSA密钥对生成失败", ex);
		}
	}

	private static SecretKey generateAesKey() throws GeneralSecurityException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		generator.init(AES_KEY_SIZE);
		return generator.generateKey();
	}

	private static byte[] encryptData(byte[] plain, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(DATA_CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH_BIT, iv));
		return cipher.doFinal(plain);
	}

	private static byte[] decryptData(byte[] encrypted, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(DATA_CIPHER);
		cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH_BIT, iv));
		return cipher.doFinal(encrypted);
	}

	private static byte[] rsaEncrypt(byte[] plain, PublicKey publicKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(WRAP_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SPEC);
		return cipher.doFinal(plain);
	}

	private static byte[] rsaDecrypt(byte[] encrypted, PrivateKey privateKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(WRAP_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SPEC);
		return cipher.doFinal(encrypted);
	}

	private static PublicKey validatePublicKey(PublicKey key) {
		if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
			throw new IllegalArgumentException("不支持的公钥算法：" + key.getAlgorithm());
		}
		return key;
	}

	private static PrivateKey validatePrivateKey(PrivateKey key) {
		if (!KEY_ALGORITHM.equalsIgnoreCase(key.getAlgorithm())) {
			throw new IllegalArgumentException("不支持的私钥算法：" + key.getAlgorithm());
		}
		return key;
	}

}
