import java.io.File;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class Sender {
  public static void main(String[] args) {
    KeyGenerator keyGen;
    SecureRandom secRandom;
    Key MACKey;
    //String myPrivateKey = "";
    String p2PublicKeyString = "";
    PublicKey p2PublicKey;
    SecretKey AESKey;
    String AESKeyString = "";
    String message = "";
    String ciphertext = "";
    String encryptedAESKey = "";
    String MAC = "";
    String aesAlgorithm = "AES/CBC/PKCS5Padding";
    String rsaAlgorithm = "RSA/CBC/PKCS1Padding";
    byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0 };
    byte[] publicKeyBytes;
    IvParameterSpec RSAIV = new IvParameterSpec(iv);
    IvParameterSpec AESIV = new IvParameterSpec(iv);

    try {
      // Generate an AES key
      AESKey = generateKey(256);
      AESKeyString = convertSecretKeyToString(AESKey);

      message = readFile("party1message.txt");

      // Encrypt our message with AES
      ciphertext = encrypt(aesAlgorithm, message, AESKey, AESIV);

      // Get the receiver's public key
      p2PublicKeyString = readFile("party2PublicKey.txt");
      publicKeyBytes = Base64.getDecoder().decode(p2PublicKeyString);
      p2PublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

      // Encrypt the AES key with the receiver's public key
      encryptedAESKey = encryptRSA(rsaAlgorithm, AESKeyString, p2PublicKey , RSAIV);

      // Generate a key to use for MAC
      keyGen = KeyGenerator.getInstance("HmacSHA256");
      secRandom = new SecureRandom();
      keyGen.init(secRandom);
      MACKey = keyGen.generateKey();

      // Generate a MAC
      MAC = generateMAC(encryptedAESKey+ciphertext, MACKey);

      // Write MAC+encryptedAESKey+ciphertext to TransmittedData

    } catch (Exception e) {
      // handle exception
      System.out.println("ERROR: " + e.getMessage());
    }
    
  }

  public static String readFile(String filename) throws FileNotFoundException {
    File file = new File(filename);
    Scanner reader = new Scanner(file);
    String data = "";
    while (reader.hasNextLine()) {
      data += reader.nextLine();
    }
    reader.close();

    return data;
  }

  public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(n);
    SecretKey key = keyGenerator.generateKey();
    return key;
  }

  public static IvParameterSpec generateIv() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
  }

  public static String convertSecretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
    byte[] rawData = secretKey.getEncoded();
    String encodedKey = Base64.getEncoder().encodeToString(rawData);
    return encodedKey;
  }

  public static String encrypt(String algorithm, String message, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    
    //Creating a cipher object
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    
    //Adding data to the cipher
    byte[] input = message.getBytes();	  
    cipher.update(input);
  
    //encrypting the data
    byte[] cipherText = cipher.doFinal();	 
    return new String(cipherText, "UTF8");
  }

  public static String encryptRSA(String algorithm, String message, PublicKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    
    //Creating a cipher object
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    
    //Adding data to the cipher
    byte[] input = message.getBytes();	  
    cipher.update(input);
  
    //encrypting the data
    byte[] cipherText = cipher.doFinal();	 
    return new String(cipherText, "UTF8");
  }

  private static String generateMAC(String message, Key key) throws NoSuchAlgorithmException, InvalidKeyException {	 
    //Creating a Mac object
    Mac mac = Mac.getInstance("HmacSHA256");

    //Initializing the Mac object
    mac.init(key);

    //Computing the Mac
    byte[] bytes = message.getBytes();      
    byte[] macResult = mac.doFinal(bytes);

    return new String(macResult);
  }
}