import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;


public class KeyGeneration {
  public static void main(String[] args) {
    try {
      KeyPair kp = generateRSAPair();
      PrivateKey privateKey = kp.getPrivate();
      PublicKey publicKey = kp.getPublic();
      String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
      String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
      writeToFile("party1PrivateKey.txt", privateKeyString);
      writeToFile("party1PublicKey.txt", publicKeyString);

    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }

  public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(n);
    SecretKey key = keyGenerator.generateKey();
    return key;
  }

  /**
   * Creates a keypair for RSA
   * @return (KeyPair)
   * @throws NoSuchAlgorithmException
   */
  public static KeyPair generateRSAPair() throws NoSuchAlgorithmException {
    //Creating KeyPair generator object
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
      
    //Initializing the key pair generator
    keyPairGen.initialize(2048);
    
    //Generating the pair of keys
    KeyPair pair = keyPairGen.generateKeyPair();

    return pair;
  }

  /**
   * Converts a SecretKey to a String
   * @param secretKey
   * @return (String)
   * @throws NoSuchAlgorithmException
   */
  public static String convertSecretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
    byte[] rawData = secretKey.getEncoded();
    String encodedKey = Base64.getEncoder().encodeToString(rawData);
    return encodedKey;
  }

  /**
   * Converts a String to a SecretKey
   * @param encodedKey
   * @return (SecretKey)
   */
  public static SecretKey convertStringToSecretKey(String encodedKey) {
    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    return originalKey;
  }

  /**
   * Writes data to the specified file
   * @param filename
   * @param data
   * @throws IOException
   */
  public static void writeToFile(String filename, String data) throws IOException {
    FileWriter writer = new FileWriter(filename);
    writer.write(data);
    writer.close();
  }

  /**
   * Generates a random IV
   * @return (IvParameterSpec)
   */
  public static IvParameterSpec generateIv() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
  }
}
