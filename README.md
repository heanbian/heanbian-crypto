# heanbian-crypto

### pom.xml

```xml

<dependency>
	<groupId>com.heanbian</groupId>
	<artifactId>heanbian-crypto</artifactId>
	<version>11.2.0</version>
</dependency>

```

注：JDK 11+ ，具体最新版本，可以到maven官网查找。

### 程序使用方法

```java

String text = "123456abc";
String ciphertext = CryptTemplate.encrypt(text);
String plaintext = CryptTemplate.decrypt(ciphertext);
System.out.println("加密：" + ciphertext);
System.out.println("解密：" + plaintext);

```
