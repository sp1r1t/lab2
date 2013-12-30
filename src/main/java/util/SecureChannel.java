package util;

import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import util.Cryptopus;
import message.request.*;
import message.response.*;

public class SecureChannel extends TCPChannel {

    private SecretKey skey;
    private IvParameterSpec spec;
    private Cipher aesCipher;

    public SecureChannel(ObjectInputStream ois, ObjectOutputStream oos,
                         SecretKey skey, IvParameterSpec spec) {
        super(ois, oos);
        this.skey = skey;
        this.spec = spec;
        try {
            aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
        } catch (Exception ex) {
        }
    }

    public Object read() throws IOException, ClassNotFoundException {
        Object o = ois.readObject();
        if (o instanceof SecureResponse) {
            SecureResponse resp = (SecureResponse) o;
            byte[] respCipher = resp.getBytes();
            try {
                aesCipher.init(Cipher.DECRYPT_MODE, skey, spec);
            } catch (Exception ex) {
            }
                //TODO
        }

        return null;
    }

    public void write(Object o) throws IOException {
        oos.writeObject(o);
    }

}