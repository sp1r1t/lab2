package util;

import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import util.Cryptopus;
import message.*;
import message.request.*;
import message.response.*;

import org.apache.log4j.*;

public class SecureChannel extends ChannelEnhancer {
    // logger
    private static Logger logger;
        {
            // set up logger
            /*logger = Logger.getLogger("SecureChannel");
            logger.setLevel(Level.DEBUG);
            BasicConfigurator.configure();*/
        }

    private SecretKey skey;
    private IvParameterSpec spec;
    private Cipher aesCipher;

    public SecureChannel(Channel channel,
                         SecretKey skey, IvParameterSpec spec) {
        super(channel);
        this.skey = skey;
        this.spec = spec;
        try {
            aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
        } catch (Exception ex) {
        }
    }

    public Object read() throws IOException, ClassNotFoundException {
        Object o = super.read();
        byte[] objCipher;
        if (o instanceof SecureResponse) {
            SecureResponse resp = (SecureResponse) o;
            objCipher = resp.getBytes();
            System.out.println("Got secure response.");
        }
        else if (o instanceof SecureRequest) {
            SecureRequest req = (SecureRequest) o;
            objCipher = req.getBytes();
            System.out.println("Got secure request.");
        }
        else {
            // object is not encrypted, shoudln't happen.
            logger.warn("Got unencrypted object.");
            return o;
        }

        byte[] objPlain = {};
        try {
            System.out.println("Decrypting object."); 
            aesCipher.init(Cipher.DECRYPT_MODE, skey, spec);
            objPlain = aesCipher.doFinal(objCipher);
        } catch (Exception ex) {
            logger.error("Couldn't init cipher.");
        }

        
        ByteArrayInputStream bis = new ByteArrayInputStream(objPlain);
        ObjectInput in = null;
        try  {
            in = new ObjectInputStream(bis);
            o = in.readObject();
        } finally {
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

    public void write(Object o) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] objCipher = {};
        try {
            System.out.println("Encrypting object.");
            aesCipher.init(Cipher.ENCRYPT_MODE, skey, spec);

            out = new ObjectOutputStream(bos);
            out.writeObject(o);
            byte[] serialObj = bos.toByteArray();
            objCipher = aesCipher.doFinal(serialObj);
        } 
        catch (Exception ex) {
            //logger.debug(ex.getMessage());
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

        Object msg;
        if (o instanceof Request) {
            msg = new SecureRequest(objCipher);
            System.out.println("Sending secure request."); 
        }
        else if (o instanceof Response) {
            msg = new SecureResponse(objCipher);
            System.out.println("Sending secure response."); 
        }
        else {
            // non-compliant message, shoudln't happen
            logger.warn("Got non-compliant message.");
            msg = o;
        }

        super.write(msg);
    }

}