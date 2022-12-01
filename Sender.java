import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

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
    //String myPrivateKey = "";
    Key p2PublicKey;
    String message = "";
    String AESKey = "";
    String ciphertext = "";
    String encryptedAESKey = "";
    String MAC = "";
    IvParameterSpec iv;

    try {
      //Creating KeyPair generator object
      KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
      
      //Initializing the key pair generator
      keyPairGen.initialize(2048);
      
      //Generating the pair of keys
      KeyPair pair = keyPairGen.generateKeyPair();

      iv = generateIv();



      //Creating a KeyGenerator object
      KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");

      //Creating a SecureRandom object
      SecureRandom secRandom = new SecureRandom();

      //Initializing the KeyGenerator
      keyGen.init(secRandom);

      //Creating/Generating a key
      Key key = keyGen.generateKey();
    
    
      ciphertext = encryptAES(message, AESKey);
      encryptedAESKey = encryptRSA(AESKey, p2PublicKey, iv);
      MAC = generateMAC(encryptedAESKey+ciphertext, key);
      // write MAC+encryptedAESKey+ciphertext to TransmittedData
    } catch (Exception e) {
      // handle exception
      System.out.println("ERROR: " + e.getMessage());
    }
    
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

  private static String encryptAES(String message, String key) {
    String result = "";
    return result;
  }

  private static String encryptRSA(String message, Key key, IvParameterSpec iv) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
    String result = "";
      
          

    //Creating a Cipher object
    Cipher cipher = Cipher.getInstance("RSA/CBC/PKCS1Padding");
      
    //Initializing a Cipher object
    cipher.init(Cipher.ENCRYPT_MODE, key);
  
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