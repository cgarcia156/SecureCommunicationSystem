import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class Sender {
  public static void main(String[] args) {
    Scanner scanner = new Scanner(System.in);
    SecretKey MACKey;
    SecretKey AESKey;
    PublicKey publicKey;
    String message = "";
    String messageFile = "";
    String publicKeyFile = "";
    String publicKeyString = "";
    String macKeyFile = "";
    byte[] ciphertext;
    byte[] encryptedAESKey;
    byte[] MAC;
    byte[] data;
    byte[] encodedKey;
    byte[] publicKeyBytes;
    byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0 };
    String aesAlgorithm = "AES/CBC/PKCS5Padding";
    IvParameterSpec AESIV = new IvParameterSpec(iv);

    try {
      System.out.println("---------------------------------------------------");

      // Generate an AES key
      AESKey = generateAESKey(256);
      
      // Read the message we want to send
      System.out.println("Enter the file for your message:");
      System.out.print(">");
      messageFile = scanner.nextLine();
      System.out.println();
      message = readFile(messageFile);

      // Encrypt our message with AES
      ciphertext = encrypt(aesAlgorithm, message, AESKey, AESIV);

      // Get the receiver's public key
      System.out.println("Enter the file containing the receiver's public key:");
      System.out.print(">");
      publicKeyFile = scanner.nextLine();
      System.out.println();
      publicKeyString = readFile(publicKeyFile);
      publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
      publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

      // Encrypt the AES key with the receiver's public key
      encryptedAESKey = encryptRSA(AESKey.getEncoded(), publicKey);

      // Generate a MAC
      data = joinByteArray(encryptedAESKey, ciphertext);
      System.out.println("Enter the file containing the mac key:");
      System.out.print(">");
      macKeyFile = scanner.nextLine();
      System.out.println();
      encodedKey = (Base64.getDecoder().decode(readFile(macKeyFile)));
      MACKey = new SecretKeySpec(encodedKey,0,encodedKey.length,"HmacSHA256");
      MAC = generateMAC(data, MACKey);
      
      // Add MAC to the beginning of data
      data = joinByteArray(MAC, data);
      
      // Write MAC+encryptedAESKey+ciphertext to TransmittedData
      writeBytes("TransmittedData.txt", data);

      scanner.close();

      System.out.println("---------------------------------------------------");

    } catch (Exception e) {
      // Handle exception
      System.out.println("ERROR: " + e.getMessage());
    }
    
  }

  /**
   * Reads the specified file
   * @param filename - the system-dependent filename
   * @return a string containing the data read from the file
   * @throws FileNotFoundException
   */
  public static String readFile(String filename) throws FileNotFoundException {
    File file = new File(filename);
    Scanner reader = new Scanner(file);

    // we just need to use \\Z as delimiter
    reader.useDelimiter("\\Z");

    String data = reader.next();
    reader.close();

    return data;
  }

  /**
   * Writes data to the specified file
   * @param filename - the system-dependent filename
   * @param data - the string to be written
   * @throws IOException
   */
  public static void writeToFile(String filename, String data) throws IOException {
    FileWriter writer = new FileWriter(filename);
    writer.write(data);
    writer.close();
  }

  /**
   * Writes a byte array to the specified file
   * @param filename - the system-dependent filename
   * @param data - the byte array to be written
   * @throws IOException
   */
  public static void writeBytes(String filename, byte[] data) throws IOException {
    File file = new File(filename);
    FileOutputStream writer = new FileOutputStream(file);
    writer.write(data);
    writer.close();
  }

  /**
   * Generates an AES key of the given length (in bits)
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
   * @throws InvalidAlgorithmParameterException
   * @throws IOException
   */
  public static byte[] encrypt(String algorithm, String message, SecretKey key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException {
    
    // Create a cipher object
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    
    // Encodes the String into bytes
    byte[] input = message.getBytes("UTF-8");
  
    // Encrypt the data
    byte[] ciphertext = cipher.doFinal(input);
    
    return ciphertext;
  }

  /**
   * Encrypts using the given algorithm, message, PublicKey, and iv
   * @param algorithm
   * @param message
   * @param key
   * @param iv
   * @return (byte[]) the ciphertext
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws UnsupportedEncodingException
   * @throws InvalidAlgorithmParameterException
   */
  public static byte[] encryptRSA(byte[] message, PublicKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    
    // Create a cipher object
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    
    // Add data to the cipher  
    cipher.update(message);
  
    // Encrypt the data
    byte[] cipherText = cipher.doFinal();	 
    return cipherText;
  }

  /**
   * Generates a MAC (HMACSHA256) of the message with the given key
   * @param message
   * @param key
   * @return (String) the MAC
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  private static byte[] generateMAC(byte[] message, Key key) throws NoSuchAlgorithmException, InvalidKeyException {	 
    //Creating a Mac object
    Mac mac = Mac.getInstance("HmacSHA256");

    //Initializing the Mac object
    mac.init(key);
    
    //Computing the Mac
    byte[] macResult = mac.doFinal(message);
    
    return macResult;
  }

  /**
   * Combines two byte arrays
   * @param byte1
   * @param byte2
   * @return byte[]
   * @throws IOException
   */
  public static byte[] joinByteArray(byte[] byte1, byte[] byte2) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write(byte1);
    outputStream.write(byte2);

    return outputStream.toByteArray();
  }
}