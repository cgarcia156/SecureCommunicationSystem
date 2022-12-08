import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
      Path filePath = Paths.get("TransmittedData.txt");
      long fileSize = Files.size(filePath);
      
      byte[] data = readBytes("TransmittedData.txt");
      byte[] MAC = Arrays.copyOfRange(data, 0, 32);

      byte[] encryptedAESKey = Arrays.copyOfRange(data, 32, 288);
      byte[] cipherText = Arrays.copyOfRange(data, 288, (int)(fileSize));

      byte[] MACinput = joinByteArray(encryptedAESKey, cipherText);

      byte[] encodedKey = (Base64.getDecoder().decode(readFile("mackey.txt")));
      SecretKey MACKey = new SecretKeySpec(encodedKey,0,encodedKey.length,"HmacSHA256");
      byte[] generatedMAC = generateMAC(MACinput, MACKey);

      boolean validMAC = Arrays.equals(MAC, generatedMAC);

      if (!validMAC) {
        System.out.println("Invalid MAC");
      } else {
        System.out.println("Message Validated");
      }


      
    } catch (Exception e) {
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

  public static byte[] readBytes(String file) throws IOException {
    Path path = Paths.get(file);
    byte[] data = Files.readAllBytes(path);
    return data;
  }

  public static String decrypt(String algorithm, byte[] cipherText, SecretKey key,
    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {
    
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, key, iv);

    byte[] plainText = cipher.doFinal(cipherText);

    return new String(plainText);
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

  public static byte[] joinByteArray(byte[] byte1, byte[] byte2) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write(byte1);
    outputStream.write(byte2);

    return outputStream.toByteArray();
  }
}
