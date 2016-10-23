package com.jservlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;

/**
 * ConfigServer Service
 *
 * curl http://localhost:8888/tclouds-service/master
 *
 * ConfigService refresh!
 * curl -d{} localhost:xxxx/refresh
 *
 * For Encrypt/Decrypt, first you need "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files",
 * new local_policy.jar and new US_export_policy.jar in \jdk1.8.0_102\jre\lib\security, now generate a RSA keystore with the keytool :
 * jdk1.8.0_102\bin>keytool -genkeypair -alias mytestkey -keyalg RSA -dname "CN=Web Server,OU=Unit,O=Organization,L=City,S=State,C=US" -keypass changeme -keystore server.jks -storepass letmein -validity 365
 *
 * Encrypt:
 * curl localhost:8888/encrypt -d mysecret
 * AQBOb9LShsaAK5dRkWT3jysWLlsbcEO+PkB9E+EZ+K1EoKGRAzKmwbEWkFt0mmQjIt+4kZauVMel+bQeyEfCLXE0glY8KNmeMvEFyAOFgzMj4f6RmqWtEGK3v9JVywPmGP2FeOzum6gMyfxbh8KBfIrjbkPwb7q7ql+8rA/HqtX+QG+Uf8fQJ9Mt8357dkcbZbYI4KSTVxGKsOGxS8YM6XJFUqF69LubHz3nirneyhTn71Ir/9lNfFCwmvdrlFIIWQYA40txRV3gFYoEVPqc7qhCFWB+ZwCMA7EGeB3C/fufHq9o5TMQgi2FnI8KudPmtXr4JcSQKxn4byxj4giv3k5j9KbhHCkl/YHWORwEmYiaCMZX64guF8nyt23twh6GBVI=
 *
 * Decrypt:
 * curl localhost:8888/decrypt -d AQBOb9LShsaAK5dRkWT3jysWLlsbcEO+PkB9E+EZ+K1EoKGRAzKmwbEWkFt0mmQjIt+4kZauVMel+bQeyEfCLXE0glY8KNmeMvEFyAOFgzMj4f6RmqWtEGK3v9JVywPmGP2FeOzum6gMyfxbh8KBfIrjbkPwb7q7ql+8rA/HqtX+QG+Uf8fQJ9Mt8357dkcbZbYI4KSTVxGKsOGxS8YM6XJFUqF69LubHz3nirneyhTn71Ir/9lNfFCwmvdrlFIIWQYA40txRV3gFYoEVPqc7qhCFWB+ZwCMA7EGeB3C/fufHq9o5TMQgi2FnI8KudPmtXr4JcSQKxn4byxj4giv3k5j9KbhHCkl/YHWORwEmYiaCMZX64guF8nyt23twh6GBVI=
 * mysecret
 *
 *
 * @author Franck Andriano 2016
 *
 */
@EnableConfigServer
@SpringBootApplication
public class ConfigServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ConfigServiceApplication.class, args);
	}
}
