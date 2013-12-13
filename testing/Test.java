import java.util.logging.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;


public class Test {

  static Logger logger = Logger.getLogger("Test");

  public static void main(String[] args) {
    try {
      LogManager.getLogManager().readConfiguration(new FileInputStream("mylogging.properties"));
    } catch (IOException x) {
      x.printStackTrace();
    }

    logger.setLevel(Level.FINE);
    logger.addHandler(new ConsoleHandler());

    logger.info("the logger says hi");

    // testing JCA functions
    String s = "p0wnys are loving creatures";

    // list all Providers
    Provider[] providers = Security.getProviders();
    System.out.println("Available Providers:");
    for (Provider p : providers) {
      System.out.println("  " + p.getName());
    }

    try {
      // MESSAGE DIGEST
      System.out.println("Message Digest");
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.update(s.getBytes());
      byte[] digest = md.digest();
      System.out.println("  MD5: " + digest);

      // SIGNING
      System.out.println("Signing"); 
      // create asym key pair
      KeyPairGenerator akeygen = KeyPairGenerator.getInstance("DSA");
      System.out.println("  Created key pair generator, the provider is " + 
                         akeygen.getProvider());
      KeyPair key = akeygen.genKeyPair();

      // create signature
      Signature sig = Signature.getInstance("DSA");

      // put signature in signing mode
      sig.initSign(key.getPrivate());
      System.out.println("  " + sig);

      // update signature to sign the message
      sig.update(s.getBytes());

      // get signature bytes
      byte[] signed = sig.sign();

      // put signature in verification mode
      sig.initVerify(key.getPublic());
      System.out.println("  " + sig);

      // update (again) with the message
      sig.update(s.getBytes());

      // verify
      if (sig.verify(signed)) {
        System.out.println("  " + s);
      } else {
        System.out.println("  nope");
      }

    } catch (NoSuchAlgorithmException ex) {
      ex.printStackTrace();
    } catch (InvalidKeyException ex) {
      ex.printStackTrace();
    } catch (SignatureException ex) {
      ex.printStackTrace();
    } 

    try {
      // CIPHER
      System.out.println("Ciphers");
      byte[] msg = s.getBytes();

      KeyGenerator skeygen = KeyGenerator.getInstance("AES");
      // note: wrong key throws runtime exception
      SecretKey aesKey = skeygen.generateKey();
      System.out.println("  key:  " + new String(aesKey.getEncoded())); 
      Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

      // encrypt
      aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
      System.out.println("  to encrypt: " + s);
      byte[] encrypted = aesCipher.doFinal(msg);
      String ciphertext = new String(encrypted);
      System.out.println("  encrypted: " + ciphertext); 

      // decrypt
      //System.out.println("  blocksize: " + aesCipher.getBlockSize());
      aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
      byte[] decrypted = aesCipher.doFinal(encrypted);
      String cleartext = new String(decrypted);
      System.out.println("  decrypted: " + cleartext); 

      // wrap (for secure transfer)
      aesCipher.init(Cipher.WRAP_MODE, aesKey);
      byte[] wrapped = aesCipher.wrap(aesKey);
      System.out.println("  wrapped:  " + new String(wrapped));
      
      // unwrap
      aesCipher.init(Cipher.UNWRAP_MODE, aesKey);
      Key unwrapped = aesCipher.unwrap(wrapped, aesKey.getAlgorithm(), Cipher.SECRET_KEY);
      System.out.println("  unwrapped:  " + new String(unwrapped.getEncoded())); 

    } catch (NoSuchAlgorithmException ex) {
      ex.printStackTrace();
    } catch (InvalidKeyException ex) {
      ex.printStackTrace();
    } catch (NoSuchPaddingException ex) {
      ex.printStackTrace();
    } catch (IllegalBlockSizeException ex) {
      ex.printStackTrace();
    } catch (BadPaddingException ex) {
      ex.printStackTrace();
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    // CIPHER STREAMS
    try {
      System.out.println("Cipher streams");
      KeyGenerator skeygen = KeyGenerator.getInstance("AES");
      // note: wrong key throws runtime exception
      SecretKey aesKey = skeygen.generateKey();
      System.out.println("  key:  " + new String(aesKey.getEncoded())); 
      Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

      // encrypt
      aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
     
      FileInputStream fis;
      FileOutputStream fos;
      CipherOutputStream cos;
      
      fis = new FileInputStream("a.txt");
      fos = new FileOutputStream("b.txt");
      cos = new CipherOutputStream(fos, aesCipher);

      byte[] b = new byte[8];
      int i = fis.read(b);
      while (i != -1) {
        cos.write(b, 0, i);
        i = fis.read(b);
      }
      cos.flush();

      // decrypt
      aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
     
      fis = new FileInputStream("b.txt");
      fos = new FileOutputStream("c.txt"); // truncated due to blocksize
      cos = new CipherOutputStream(fos, aesCipher);

      b = new byte[8];
      i = fis.read(b);
      while (i != -1) {
        cos.write(b, 0, i);
        i = fis.read(b);
      }
      cos.flush();

      
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    
  }
}