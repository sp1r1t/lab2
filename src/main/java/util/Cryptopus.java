package util;

import java.io.*;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.*;

public class Cryptopus {
    public static Object decryptObject(byte[] ciphertxt, PrivateKey key)
        throws Exception {
        Cipher cipher = Cipher.getInstance(
            "RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
            
        byte[] serialObj = cipher.doFinal(ciphertxt);
            
        ByteArrayInputStream bis = new ByteArrayInputStream(serialObj);
        ObjectInput in = null;
        Object o = null;
        try {
            in = new ObjectInputStream(bis);
            o = in.readObject();
        } finally {
            try {
                bis.close();
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException Exception ) {
                // ignore close exception
            }
        }
        return o;
    }

    public static byte[] encryptObject(Object o, PublicKey key) 
        throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        try {
            // init cipher
            Cipher cipher = Cipher.getInstance(
                "RSA/NONE/OAEPWithSHA256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
                
            // serialize request
            out = new ObjectOutputStream(bos);   
            out.writeObject(o);
            byte[] serialObj = bos.toByteArray();

            // return ciphertext
            return cipher.doFinal(serialObj);
        }
        finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
            }
            try {
                bos.close();
            } catch (IOException ex) {
            }
        }
    }

}