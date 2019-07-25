# heanbian-crypto
通用加密解密工具包

1.pom.xml
```
<dependencies>
 <dependency>
  <groupId>com.heanbian</groupId>
  <artifactId>heanbian-crypto</artifactId>
  <version>5.0.0</version>
 </dependency>
</dependencies>
```

2.Examples
``` 
String text = "123456abc";
String ciphertext = CryptTemplate.encrypt(text);
String plaintext = CryptTemplate.decrypt(ciphertext);
System.out.println("加密：" + ciphertext);
System.out.println("解密：" + plaintext);
```
