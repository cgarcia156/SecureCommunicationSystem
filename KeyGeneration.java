import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Used to generate keys for the secure communication system
 */
public class KeyGeneration {
  public static void main(String[] args) {
    try {
      KeyPair kp = generateRSAPair();
      PrivateKey privateKey = kp.getPrivate();
      PublicKey publicKey = kp.getPublic();
      String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
      String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
      Key MACKey = generateMACKey();
      byte[] iv = generateIv().getIV();
      
      writeToFile("iv.txt", Base64.getEncoder().encodeToString(iv));
      writeToFile("mac_key.txt", Base64.getEncoder().encodeToString(MACKey.getEncoded()));
      writeToFile("my_private_key.txt", privateKeyString);
      writeToFile("my_public_key.txt", publicKeyString);

    } catch (Exception e) {
      System.out.println(e.getMessage());
    }
  }

  /**
   * Generates a MAC key <i>(HMACSHA256)</i>
   * @return the new MAC key
   * @throws NoSuchAlgorithmException
   */
  public static Key generateMACKey() throws NoSuchAlgorithmException {
    // Generate a key to use for MAC
    KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
    SecureRandom secRandom = new SecureRandom();
    keyGen.init(secRandom);
    return keyGen.generateKey();
  }

  /**
   * Creates a keypair for RSA
   * @return the generated key pair
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
   * @param secretKey - the secret key
   * @return A String containing the resulting Base64 encoded characters
   * @throws NoSuchAlgorithmException
   */
  public static String convertSecretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
    byte[] rawData = secretKey.getEncoded();
    String encodedKey = Base64.getEncoder().encodeToString(rawData);
    return encodedKey;
  }

  /**
   * Converts a String to a SecretKey <i>(AES)</i>
   * @param encodedKey - the key encoded as a String
   * @return the secret key
   */
  public static SecretKey convertStringToSecretKey(String encodedKey) {
    byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
    SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    return originalKey;
  }

  /**
   * Writes data to the specified file
   * @param filename - The system-dependent filename
   * @param data - the String to be written
   * @throws IOException
   */
  public static void writeToFile(String filename, String data) throws IOException {
    FileWriter writer = new FileWriter(filename);
    writer.write(data);
    writer.close();
  }

  /**
   * Generates a random IV
   * @return the iv
   */
  public static IvParameterSpec generateIv() {
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
  }
}
