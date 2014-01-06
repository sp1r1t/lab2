package util;

import java.io.*;
import java.security.*;
import javax.crypto.*;

import message.*;
import message.request.*;
import message.response.*;

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

    public static Object bytes2object(byte[] bytes) {
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInput in = null;
        Object o = null;;
        try  {
            in = new ObjectInputStream(bis);
            o = in.readObject();
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }finally {
            try {
                bis.close();
            } catch (IOException  ex) {
            }
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
            }
        }
        return o;
    }

    public static byte[] object2bytes(Object o) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] bytes = {};
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(o);
            bytes = bos.toByteArray();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }finally {
            try {
                bos.close();
            } catch (IOException  ex) {
            }
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
            }
        }            
        return bytes;
    }

    public static HmacRequest packHmac(Request req, Key hmacKey) {
        byte[] objBytes = object2bytes(req);
        byte[] hash = getHmac(hmacKey).doFinal(objBytes);
        return new HmacRequest(req, hash);
    }

    public static Response packHmac(Response resp, Key hmacKey) {
        byte[] objBytes = object2bytes(resp);
        byte[] hash = getHmac(hmacKey).doFinal(objBytes);
        return new HmacResponse(resp, hash);
    }

    public static Request unpackHmac(HmacRequest hreq, Key hmacKey) {
        Request req = hreq.getRequest();
        byte[] objBytes = object2bytes(req);
        byte[] hash = getHmac(hmacKey).doFinal(objBytes);

        if (MessageDigest.isEqual(hash, hreq.getHash())) {
            System.out.println("Hash is good.");
            return req;
        }
        else {
            System.out.println("Hash is bad.");
            return null;
        }
    }

    public static Response unpackHmac(HmacResponse hresp, Key hmacKey) {
        Response resp = hresp.getResponse();
        byte[] objBytes = object2bytes(resp);
        byte[] hash = getHmac(hmacKey).doFinal(objBytes);

        if (MessageDigest.isEqual(hash, hresp.getHash())) {
            System.out.println("Hash is good.");
            return resp;
        }
        else {
            System.out.println("Hash is bad.");
            return null;
        }
    }

    private static Mac getHmac(Key hmacKey) {
        Mac hmac = null;
        try {
            hmac = Mac.getInstance("HmacSHA256", "BC");
            hmac.init(hmacKey);
        } catch (Exception ex) {
            System.out.println("get hmac: " + ex.getMessage()); 
        }
        return hmac;
    }
}