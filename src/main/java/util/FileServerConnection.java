package util;

import message.*;
import message.response.*;
import message.request.*;

import java.util.concurrent.Callable;
import java.security.*;
import javax.crypto.*;
import java.net.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.apache.log4j.Logger;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;

public class FileServerConnection implements Callable {
    private Logger logger;
    private String host;
    private Integer port;
    private Request request;
    private Key hmacKey = null;

    public FileServerConnection(String host, Integer port, Request request) {
        logger = Logger.getLogger(FileServerConnection.class);
        logger.setLevel(Level.toLevel("DEBUG"));
        this.host = host;
        this.port = port;
        this.request = request;
    }

    public FileServerConnection(String host, Integer port, Request request,
        Key hmacKey) {
        logger = Logger.getLogger(FileServerConnection.class);
        logger.setLevel(Level.toLevel("DEBUG"));
        this.host = host;
        this.port = port;
        this.request = request;
        this.hmacKey = hmacKey;
    }

    public Response call() {
        Socket socket = null;
        ObjectOutputStream oos;
        ObjectInputStream ois;
        Response response = null;

        if (hmacKey != null) {
            logger.debug("Packing hmac request for: " + request.getClass() + "."); 
            request = Cryptopus.packHmac(request, hmacKey);
        }

        try {
            logger.debug("Connectiong to " + host + ":" + port+ ".");
            socket = new Socket(host, port);

            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
                
            logger.debug("Writing request to fs.");
            oos.writeObject(request);

            logger.debug("Reading request from fs.");
            Object o = ois.readObject();

            if(o != null) {
                logger.debug("Got Response.");
                // check for hmac
                if (o instanceof HmacResponse) {
                    HmacResponse hresp = (HmacResponse) o;
                    logger.debug("Unpacking hmac response."); 
                    response = Cryptopus.unpackHmac(hresp, hmacKey);
                }
                else if (o instanceof Response) {
                    response = (Response) o;
                }
                else {
                    logger.warn("Response corrupted.");
                }
            } else {
                logger.warn("Response corrupted (== null).");
            }
        } catch(UnknownHostException x) {
            logger.info("Host not known.");
        } catch(IOException x) {
            logger.info("Coudln't connect to file server.");
            x.printStackTrace();
        } catch (ClassNotFoundException x) {
            logger.info("Class not found.");
        }

        logger.debug("Returning.");
        return response;
    }
}
