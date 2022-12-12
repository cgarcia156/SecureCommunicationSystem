import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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
    String ivFile = "";
    String publicKeyFile = "";
    String publicKeyString = "";
    String macKeyFile = "";
    byte[] ciphertext;
    byte[] encryptedAESKey;
    byte[] MAC;
    byte[] data;
    byte[] encodedKey;
    byte[] publicKeyBytes;
    byte[] iv;
    String aesAlgorithm = "AES/CBC/PKCS5Padding";
    IvParameterSpec AESIV;

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

      // Read the iv
      System.out.println("Enter the file containing the initialization vector:");
      System.out.print(">");
      ivFile = scanner.nextLine();
      System.out.println();
      iv = Base64.getDecoder().decode(readFile(ivFile));
      AESIV = new IvParameterSpec(iv);

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
   * @param keySize - the key size in bits
   * @return the new key
   * @throws NoSuchAlgorithmException
   */
  public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(keySize);
    SecretKey key = keyGenerator.generateKey();
    return key;
  }

  /**
   * Encrypts a message with the specified algorithm, SecretKey, and iv
   * @param algorithm - the name of the transformation, e.g., <i>AES/CBC/PKCS5Padding</i>. See the Cipher
   * section in the Java Security Standard Algorithm Names Specification for information about standard
   * transformation names.
   * @param message - the message
   * @param key - the SecretKey
   * @param iv - the initialization vector
   * @return a byte array containing the ciphertext
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidAlgorithmParameterException
   * @throws InvalidKeyException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws UnsupportedEncodingException
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
   * Encrypts a message using <i>RSA/ECB/PKCS1Padding</i>
   * @param message - the message to be encrypted
   * @param key - the public key of the receiver
   * @return a byte array containing the ciphertext
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
  
    // Encrypt the data
    byte[] ciphertext = cipher.doFinal(message);	 
    return ciphertext;
  }

  /**
   * Generates a MAC <i>(HMACSHA256)</i> of the message with the given key
   * @param message - the data in bytes
   * @param key - the key
   * @return the MAC result
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
   * Combines two byte arrays into one
   * @param byte1 - the first byte array containing data
   * @param byte2 - the second byte array containing data
   * @return a byte array containing the data
   * @throws IOException
   */
  public static byte[] joinByteArray(byte[] byte1, byte[] byte2) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write(byte1);
    outputStream.write(byte2);

    return outputStream.toByteArray();
  }
}