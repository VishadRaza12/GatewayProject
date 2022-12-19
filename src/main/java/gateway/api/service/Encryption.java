package gateway.api.service;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class Encryption {
    private static final Logger logger = LoggerFactory.getLogger(Encryption.class);

	static ObjectMapper mapper = new ObjectMapper();
	
	private static SecretKeySpec secretKey;
	private static byte[] key;

	public static void setKey(String myKey) throws JsonProcessingException
	{
        logger.info("In Encryption class");
        logger.debug("Method Call : setKey(myKey="+myKey+")");

	    MessageDigest sha = null;
	    try {
	        key = myKey.getBytes("UTF-8");
	        sha = MessageDigest.getInstance("SHA-1");
            logger.debug("This is MessageDigest object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(sha));

	        key = sha.digest(key);
	        key = Arrays.copyOf(key, 16);
            logger.debug("This is key: "+key);

	        secretKey = new SecretKeySpec(key, "AES");
            logger.debug("This is secretKey: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(secretKey));

	    }
	    catch (NoSuchAlgorithmException e) {
            logger.error("No such algorithm exists. "+e.getMessage());
	        e.printStackTrace();
	    }
	    catch (UnsupportedEncodingException e) {
            logger.error("Unsupported encoding exception occurred. "+e.getMessage());
	        e.printStackTrace();
	    }
	}
public static String encrypt(String strToEncrypt, String secret)
{
    logger.info("In Encryption class");
    logger.debug("Method Call : encrypt(strToEncrypt="+strToEncrypt+",secret="+secret+")");

    try
    {
        setKey(secret);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        logger.debug("This is Cipher: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(cipher));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        String encrypt= Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        logger.debug("RESPONSE: This is the returned encrypted string: "+encrypt);
        return encrypt;
    }
    catch (Exception e)
    {
        logger.error("Exception occurred while encrypting. "+e.getMessage());
        System.out.println("Error while encrypting: " + e.toString());
    }
    return null;
}

public String decrypt(String cipherText, String secret) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException
{

    logger.info("In Encryption class");
    logger.debug("Method Call : decrypt(cipherText="+cipherText+",secret="+secret+")");

	byte[] cipherData = Base64.getDecoder().decode(cipherText);
    logger.debug("This is cipherData: "+cipherData);

	byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);
    logger.debug("This is saltData: "+saltData);


	MessageDigest md5 = MessageDigest.getInstance("MD5");
    logger.debug("This is MessageDigest: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(md5));

	final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, saltData, secret.getBytes(StandardCharsets.UTF_8), md5);
	SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "AES");
    logger.debug("This is SecretKeySpec: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(key));

	IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);
    logger.debug("This is IvParameterSpec: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(iv));

	byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
	Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
    logger.debug("This is Cipher: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(aesCBC));

	aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
	byte[] decryptedData = aesCBC.doFinal(encrypted);
    logger.debug("This is decryptedData: "+decryptedData);

	String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);
    logger.debug("RESPONSE: This is decryptedText: "+decryptedText);

	return decryptedText;
}
public static byte[][] GenerateKeyAndIV(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md) throws JsonProcessingException {

    logger.info("In Encryption class");
    logger.debug("Method Call : GenerateKeyAndIV(md, keyLength="+keyLength+",ivLength="+ivLength+",iterations="+iterations+",salt="+salt+",password="+password+")");
    logger.debug("REQUEST (MessageDigest) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(md));


    int digestLength = md.getDigestLength();
    logger.debug("This is digestLength integer: "+digestLength);

    int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
    logger.debug("This is requiredLength integer: "+requiredLength);

    byte[] generatedData = new byte[requiredLength];
    int generatedLength = 0;

    try {
        md.reset();

        // Repeat process until sufficient data has been generated
        while (generatedLength < keyLength + ivLength) {

            // Digest data (last digest if available, password data, salt if available)
            if (generatedLength > 0)
                md.update(generatedData, generatedLength - digestLength, digestLength);
            md.update(password);
            if (salt != null)
                md.update(salt, 0, 8);
            md.digest(generatedData, generatedLength, digestLength);

            // additional rounds
            for (int i = 1; i < iterations; i++) {
                md.update(generatedData, generatedLength, digestLength);
                md.digest(generatedData, generatedLength, digestLength);
            }

            generatedLength += digestLength;
        }
        logger.debug("This is generatedLength integer: "+generatedLength);

        // Copy key and IV into separate byte arrays
        byte[][] result = new byte[2][];
        result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
        if (ivLength > 0)
            result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);

        logger.debug("RESPONSE: This is result byte array: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result));
        return result;

    } catch (DigestException e) {
        logger.error("Digest exception occurred. "+e.getMessage());
        throw new RuntimeException(e);

    } finally {
        // Clean out temporary data
        Arrays.fill(generatedData, (byte)0);
    }
}
}