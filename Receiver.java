import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
  public static void main(String[] args) {
    String aesAlgorithm = "AES/CBC/PKCS5Padding";
    byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0 };
    IvParameterSpec AESIV = new IvParameterSpec(iv);
    try {
      System.out.println("---------------------------------------------------");
      Path filePath = Paths.get("TransmittedData.txt");
      long fileSize = Files.size(filePath);
      
      byte[] data = readBytes("TransmittedData.txt");
      byte[] MAC = Arrays.copyOfRange(data, 0, 32);

      byte[] encryptedAESKey = Arrays.copyOfRange(data, 32, 288);
      byte[] ciphertext = Arrays.copyOfRange(data, 288, (int)(fileSize));

      byte[] MACinput = joinByteArray(encryptedAESKey, ciphertext);

      byte[] encodedMACKey = (Base64.getDecoder().decode(readFile("mackey.txt")));
      SecretKey MACKey = new SecretKeySpec(encodedMACKey,0,encodedMACKey.length,"HmacSHA256");
      byte[] generatedMAC = generateMAC(MACinput, MACKey);

      boolean validMAC = Arrays.equals(MAC, generatedMAC);

      if (!validMAC) {
        System.out.println("Invalid MAC");
      } else {
        System.out.println("Message Validated");
      }

      // Get our private key
      String p2PrivateKeyString = readFile("party2PrivateKey.txt");
      byte[] privateKeyBytes = Base64.getDecoder().decode(p2PrivateKeyString);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PrivateKey p2PrivateKey = kf.generatePrivate(keySpec);

      byte[] encodedAESKey = decryptRSA(encryptedAESKey, p2PrivateKey);
      SecretKey AESKey = new SecretKeySpec(encodedAESKey, 0, encodedAESKey.length, "AES");
      
      String message = decrypt(aesAlgorithm, ciphertext, AESKey, AESIV);
      System.out.println("\nDecrypted Message:\n");
      System.out.println(message);
      System.out.println("---------------------------------------------------");
      
    } catch (Exception e) {
      System.out.println("ERROR: " + e.getMessage());
    }
    
  }

  /**
   * Reads the specified file
   * @param filename - the string path to the file
   * @return a string containing the data read from the file
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
   * Reads all bytes in a file. Note that this method is intended for simple cases where it is convenient to
   * read all bytes into a byte array. It is not intended for reading in large files.
   * @param filename - the path string to the file
   * @return a byte array containing the bytes read from the file
   * @throws IOException
   */
  public static byte[] readBytes(String filename) throws IOException {
    Path path = Paths.get(filename);
    byte[] data = Files.readAllBytes(path);
    return data;
  }

  /**
   * Decrypts ciphertext with the specified algorithm, SecretKey, and iv
   * @param algorithm - the name of the transformation, e.g., <i>AES/CBC/PKCS5Padding</i>. See the Cipher
   * section in the Java Security Standard Algorithm Names Specification for information about standard
   * transformation names.
   * @param ciphertext - a byte array containing the ciphertext
   * @param key - the SecretKey
   * @param iv - the initialization vector
   * @return a string containing the decrypted plaintext
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws InvalidAlgorithmParameterException
   * @throws InvalidKeyException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws UnsupportedEncodingException
   */
  public static String decrypt(String algorithm, byte[] ciphertext, SecretKey key, IvParameterSpec iv
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, key, iv);

    byte[] plaintext = cipher.doFinal(ciphertext);

    return new String(plaintext, "UTF-8");
  } 

  /**
   * Decrypts ciphertext using <i>RSA/ECB/PKCS1Padding</i>
   * @param ciphertext - the ciphertext to be decrypted
   * @param key - a private key
   * @return a byte array containing the decrypted text
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   * @throws UnsupportedEncodingException
   * @throws InvalidAlgorithmParameterException
   */
  public static byte[] decryptRSA(byte[] ciphertext, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
    
    // Create a cipher object
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, key);
    
    // Add data to the cipher
    cipher.update(ciphertext);
  
    // Encrypt the data
    byte[] plaintext = cipher.doFinal();	 
    return plaintext;

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
