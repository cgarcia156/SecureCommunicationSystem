import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

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
      AESKey = generateAESKey(256);
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
      writeToFile("TransmittedData.txt", MAC+encryptedAESKey+ciphertext);

    } catch (Exception e) {
      // Handle exception
      System.out.println("ERROR: " + e.getMessage());
    }
    
  }

  /**
   * Reads the specified file
   * @param filename
   * @return (String) data
   * @throws FileNotFoundException
   */
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
   * Generates an AES key of the given length
   * @param keySize
   * @return (SecretKey) key
   * @throws NoSuchAlgorithmException
   */
  public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(keySize);
    SecretKey key = keyGenerator.generateKey();
    return key;
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
   * Encrypts using the given algorithm, message, SecretKey, and iv
   * @param algorithm
   * @param message
   * @param key
   * @param iv
   * @return (String) the ciphertext
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws UnsupportedEncodingException
   * @throws InvalidAlgorithmParameterException
   */
  public static String encrypt(String algorithm, String message, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    
    // Create a cipher object
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    
    // Add data to the cipher
    byte[] input = message.getBytes();	  
    cipher.update(input);
  
    // Encrypt the data
    byte[] cipherText = cipher.doFinal();	 
    return new String(cipherText, "UTF8");
  }

  /**
   * Encrypts using the given algorithm, message, PublicKey, and iv
   * @param algorithm
   * @param message
   * @param key
   * @param iv
   * @return (String) the ciphertext
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws UnsupportedEncodingException
   * @throws InvalidAlgorithmParameterException
   */
  public static String encryptRSA(String algorithm, String message, PublicKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    
    // Create a cipher object
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    
    // Add data to the cipher
    byte[] input = message.getBytes();	  
    cipher.update(input);
  
    // Encrypt the data
    byte[] cipherText = cipher.doFinal();	 
    return new String(cipherText, "UTF8");
  }

  /**
   * Generates a MAC (HMACSHA256) of the message with the given key
   * @param message
   * @param key
   * @return (String) the MAC
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
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