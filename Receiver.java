import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Receiver {
  public static void main(String[] args) {
    try {
      Path filePath = Paths.get("TransmittedData.txt");
      long fileSize = Files.size(filePath);
      
      byte[] data = read("TransmittedData.txt");
      byte[] MAC = Arrays.copyOfRange(data, 0, 32);
      byte[] encryptedAESKey = Arrays.copyOfRange(data, 32, 288);
      byte[] cipherText = Arrays.copyOfRange(data, 288, (int)(fileSize - 288));

      System.out.println(Base64.getEncoder().encodeToString(MAC));
      System.out.println();
      System.out.println(Base64.getEncoder().encodeToString(encryptedAESKey));
      System.out.println();
      System.out.println(Base64.getEncoder().encodeToString(cipherText));


      
    } catch (Exception e) {
      System.out.println("ERROR: " + e.getMessage());
    }
    
  }

  // public static byte[] readBytes(String filePath, int start, int size) throws IOException {
  //     File binaryFile = new File(filePath);
  //     RandomAccessFile randomAccessFile = new RandomAccessFile(binaryFile, "r");
  //     FileChannel binaryFileChannel = randomAccessFile.getChannel();

  //     randomAccessFile.close();
  //     return binaryFileChannel.map(FileChannel.MapMode.READ_ONLY, start, size).array();
  // }

  public static byte[] read(String file) throws IOException {
    Path path = Paths.get(file);
    byte[] data = Files.readAllBytes(path);
    return data;
  }

  

  public static String decrypt(String algorithm, String cipherText, SecretKey key,
    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException {
    
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, key, iv);

    byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));

    return new String(plainText);
} 
}
