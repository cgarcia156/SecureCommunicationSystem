import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

public class Sender {
  public static void main(String[] args) {
    //String myPrivateKey = "";
    String p2PublicKey = "";
    String message = "";
    String AESKey = "";
    String ciphertext = "";
    String encryptedAESKey = "";
    String MAC = "";

    //Creating a KeyGenerator object
    KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");

    //Creating a SecureRandom object
    SecureRandom secRandom = new SecureRandom();

    //Initializing the KeyGenerator
    keyGen.init(secRandom);

    //Creating/Generating a key
    Key key = keyGen.generateKey();
    
    try {
      ciphertext = encryptAES(message, AESKey);
      encryptedAESKey = encryptRSA(AESKey, p2PublicKey);
      MAC = generateMAC(encryptedAESKey+ciphertext);
      // write MAC+encryptedAESKey+ciphertext to TransmittedData
    } catch (Exception e) {
      // handle exception
      System.out.println("ERROR: " + e.getMessage());
    }
    
  }

  private static String encryptAES(String message, String key) {
    String result = "";
    return result;
  }

  private static String encryptRSA(String message, String key) {
    String result = "";
    return result;
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