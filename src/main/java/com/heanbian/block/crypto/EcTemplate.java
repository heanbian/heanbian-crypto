package com.heanbian.block.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EcTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String ALGORITHM = "EC";
	private static final String TRANSFORMATION = "ECIES"; // 使用 ECIES 作为推荐的加密模式

	private PublicKey publicKey;
	private PrivateKey privateKey;

	public EcTemplate() {
		KeyPair keyPair = generateKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	private KeyPair generateKeyPair() {
		try {
			EllipticCurve ellipticCurve = new EllipticCurve(
					new ECFieldFp(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
					new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
					new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16));
			ECPoint ecPoint = new ECPoint(
					new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
					new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16));
			ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, ecPoint,
					new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16), 1);

			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
			keyPairGenerator.initialize(ecParameterSpec);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException("Failed to generate EC key pair", e);
		}
	}

	public String encrypt(String content) {
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
			byte[] encryptedBytes = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
			return Base64.getUrlEncoder().encodeToString(encryptedBytes);
		} catch (Exception e) {
			throw new RuntimeException("Encryption failed", e);
		}
	}

	public String decrypt(String encryptedContent) {
		try {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(encryptedContent));
			return new String(decryptedBytes, StandardCharsets.UTF_8).strip();
		} catch (Exception e) {
			throw new RuntimeException("Decryption failed", e);
		}
	}

	public String getPublicKeyString() {
		return Base64.getUrlEncoder().encodeToString(this.publicKey.getEncoded());
	}

	public String getPrivateKeyString() {
		return Base64.getUrlEncoder().encodeToString(this.privateKey.getEncoded());
	}

	public PublicKey loadPublicKey(String publicKeyString) {
		try {
			byte[] encodedKey = Base64.getUrlDecoder().decode(publicKeyString);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
			return factory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load public key", e);
		}
	}

	public PrivateKey loadPrivateKey(String privateKeyString) {
		try {
			byte[] encodedKey = Base64.getUrlDecoder().decode(privateKeyString);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
			return factory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new RuntimeException("Failed to load private key", e);
		}
	}

}