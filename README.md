# heanbian-crypto
通用加密解密工具包

1.pom.xml
```
<dependencies>
 <dependency>
  <groupId>com.heanbian</groupId>
  <artifactId>heanbian-crypto</artifactId>
  <version>4.0.8</version>
 </dependency>
</dependencies>
```

2.Examples
``` 
String text = "123456abc";
String ciphertext = HCryptTemplate.encrypt(text);
String plaintext = HCryptTemplate.decrypt(ciphertext);
System.out.println("加密：" + ciphertext);
System.out.println("解密：" + plaintext);
```
