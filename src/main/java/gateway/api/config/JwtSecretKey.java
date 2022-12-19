package gateway.api.config;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import gateway.api.model.JWT.JwtConfiguration;
import gateway.api.repository.JwtConfigurationRepository;


@Service
public class JwtSecretKey {
    @Autowired
    JwtConfigurationRepository jwtConfigurationRepository;
    JwtConfiguration jwt;

    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String ALGORITHM = "AES/CBC/PKCS5PADDING";

    public void prepareSecreteKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes(Charset.defaultCharset());
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String strToEncrypt, String secret) {
        try {
            String iv = jwt.getInitializationvector();
            byte[] initVector = Base64.getDecoder().decode(iv.getBytes(StandardCharsets.UTF_8));
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey,ivParameterSpec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(JwtConfiguration jwt, String strToDecrypt, String secret) {
        try {
        	if(jwt == null) {
        		jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();	
        	}
            String base64EncodedSecret = secret;
            byte[] decodedSecret = Base64.getDecoder().decode(base64EncodedSecret);
            String str = new String(decodedSecret);
            prepareSecreteKey(str);
            String iv = jwt.getInitializationvector();
            byte[] initVector = Base64.getDecoder().decode(iv.getBytes(StandardCharsets.UTF_8));
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey,ivParameterSpec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

}