package com.heanbian.block.crypto;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NullCipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.UrlBase64;

public class EcTemplate {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	static final String ALG = "EC";
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public EcTemplate() {
		KeyPair keyPair = getKeyPair();
		this.publicKey = keyPair.getPublic();
		this.privateKey = keyPair.getPrivate();
	}

	public KeyPair getKeyPair() {
		EllipticCurve ellipticCurve = new EllipticCurve(
				new ECFieldFp(new BigInteger(
						"115792089210356248762697446949407573530086143415290314195533631308867097853951")),
				new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
				new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
		ECPoint ecPoint = new ECPoint(
				new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
				new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
		ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, ecPoint,
				new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"), 1);

		KeyPairGenerator k;
		try {
			k = KeyPairGenerator.getInstance(ALG);
			k.initialize(ecParameterSpec);
			return k.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String encrypt(String content) {
		Cipher cipher;
		try {
			cipher = new NullCipher();
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
			byte[] encoded = cipher.doFinal(content.getBytes());
			return new String(UrlBase64.encode(encoded), Charset.defaultCharset());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String decrypt(String content) {
		Cipher cipher;
		try {
			cipher = new NullCipher();
			cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] decoded = cipher.doFinal(UrlBase64.decode(content));
			return new String(decoded, Charset.defaultCharset());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public String getPublicKey() {
		return new String(UrlBase64.encode(this.publicKey.getEncoded()), Charset.defaultCharset());
	}

	public String getPrivateKey() {
		return new String(UrlBase64.encode(this.privateKey.getEncoded()), Charset.defaultCharset());
	}

	public PublicKey getPublicKey(String publicKey) {
		byte[] encodedKey = UrlBase64.decode(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance(ALG);
			return factory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public PrivateKey getPrivateKey(String privateKey) {
		byte[] encodedKey = UrlBase64.decode(privateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
		KeyFactory factory;
		try {
			factory = KeyFactory.getInstance(ALG);
			return factory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}