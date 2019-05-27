# heanbian-crypto
通用加密解密工具包

1.pom.xml
```
<dependencies>
	<dependency>
		<groupId>com.heanbian</groupId>
		<artifactId>heanbian-crypto</artifactId>
		<version>${version}</version>
	</dependency>
</dependencies>
```

2.Example
``` 
HCryptTemplate tmp = HCryptTemplate.INSTANCE;
String text = "123456abc";
String ciphertext = tmp.encrypt(text);
String plaintext = tmp.decrypt(ciphertext);
System.out.println("加密：" + ciphertext);
System.out.println("解密：" + plaintext);
```