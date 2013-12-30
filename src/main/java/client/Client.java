package client;

import java.util.*;
import java.util.regex.*;
import java.util.concurrent.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import cli.*;
import util.*;
import client.*;
import message.*;
import message.request.*;
import message.response.*;
import model.*;

import org.apache.log4j.*;
//import org.apache.commons.codec.binary.Hex;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.openssl.*;
import org.bouncycastle.jce.provider.*;

/**
 * The Client
 */
public class Client {
    /**
     * private variables
     */
    // name of the client
    private String name;

    // logger
    private Logger logger;
        {
            // set up logger
            logger = Logger.getLogger("Client");
            BasicConfigurator.configure();
            logger.setLevel(Level.DEBUG);
            logger.debug("Logger is set up.");
        }

    // config
    private Config config;

    // download directory
    private String downloadDir;

    // proxy hostname
    private String proxy;

    // port for proxy connection
    private Integer tcpPort;

    // proxy public key
    private PublicKey proxyPubKey;
    
    // user private key
    private PrivateKey privateKey;

    // user public key
    private PublicKey publicKey;

    // the shell
    private Shell shell;

    // command interface
    private IClientCli cli;
    
    // thread pool
    private ExecutorService pool;

    // socket to connect to proxy
    private Socket proxySocket;

    // io streams
    private PrintWriter out;
    private BufferedReader in;

    private ObjectOutputStream oos;
    private ObjectInputStream ois;

    // session id
    private UUID sid;

    // user pw
    private String pw;

    // AES cipher
    private Cipher aesCipher;

    /**
     * main function
     */
    public static void main(String[] args) {
        Client client = new Client("client");
        client.run();
        return;
    }

    /**
     * Constructor
     */
    public Client(String name) {
        this.name = name;
        this.config = new Config(name);
        this.shell = new Shell(name, System.out, System.in);
    }

    public Client(String name, Config config, Shell shell) {
        this.name = name;
        this.config = config;
        this.shell = shell;
    }

    public void run() {
        // make bouncy caslte provider default
        Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.insertProviderAt(prov, 1);

        // read config
        String key = name;
        try {
            key = "download.dir";
            downloadDir = config.getString(key);
            key = "proxy.host";
            proxy = config.getString(key);
            key = "proxy.tcp.port";
            tcpPort = config.getInt(key);
        } catch (MissingResourceException x) {
            if(key == name) {
                logger.fatal("Config " + key + 
                             ".properties does not exist.");
            } else {
                logger.fatal("Key " + key + " is not defined.");
            }
            System.exit(1);
        }

        // read proxy pub key
/*        try {
          String proxyPubKeyString = readKey("proxy", "public");
          proxyPubKey = convertKeyToKeyObject(proxyPubKeyString);
          logger.debug("key: " + proxyPubKey.getEncoded());
          } catch (IOException ex) {
          logger.fatal("Couldn't read proxys public key.");
          System.exit(1);
          } catch (Exception ex) {
          ex.printStackTrace();
          }
*/
        try {
            proxyPubKey = readPublicKey("proxy");
        } catch (IOException  ex) {
            logger.fatal("Couldn't read proxys public key.");
            System.exit(1);
        }

        // set up thread pool
        pool = Executors.newFixedThreadPool(10);

        // connect to proxy
        proxySocket = null;
        try {
            proxySocket = new Socket(proxy, tcpPort);

            oos = new ObjectOutputStream(proxySocket.getOutputStream());
            ois = new ObjectInputStream(proxySocket.getInputStream());

            out = new PrintWriter(proxySocket.getOutputStream(), true);
            in =  new BufferedReader(
                new InputStreamReader(proxySocket.getInputStream()));

        } catch(UnknownHostException x) {
            logger.info("Host not known.");
            logger.info("Shutting down client.");
            return;
        } catch(IOException x) {
            logger.info("Couldn't connect to proxy.");
            logger.info("Shutting down client.");
            return;
        } 

        // set up shell
        cli = new ClientCli();
        shell.register(cli);
        logger.info("Starting the shell.");
        Future shellfuture = pool.submit(shell);

        System.out.println("Client started."); 

        /*
        // for now join shell
        try {
        shellfuture.get();
        } catch (InterruptedException x) {
        logger.info("Caught interrupt while waiting for shell.");
        } catch (ExecutionException x) {
        logger.info("Caught ExecutionExcpetion while waiting for shell.");
        } */

        logger.info("Closing main.");
    }

    /**
     * >> depricated!
     * Reads the key with the specified name from the keys directory. Type
     * can be public or private and will define the filename extension. If
     * type as another value just the name will be used.
     */
    private PublicKey readKey(String name, String type) throws IOException {
        if (type.equals("private")) { 
            type = ".pem";
        }
        else if (type.equals("public")) {
            type = ".pub.pem";
        }
        else {
            type = "";
        }

        Charset charset = Charset.forName("UTF-8");
        Path file = Paths.get("keys/" + name + type);
        BufferedReader reader = null;
        String key = "";
        reader = Files.newBufferedReader(file,charset);
        PEMReader parser = new PEMReader(reader);
        Object o = parser.readObject();
        logger.debug(o.getClass()); 
        if (o instanceof JCERSAPublicKey) {
            return (JCERSAPublicKey) o;
        } else {
            logger.error("Wrong key type");
            return null;
        }


        /*while (reader.ready()) {
          String line = reader.readLine();
          if (line.matches(".*-.*")) {
          continue;
          }
          key += line;
        
          reader.close();*/
        //logger.debug("keystring:\n" + key);
        //return key;
    }

    private PublicKey readPublicKey(String name) throws IOException {
        Charset charset = Charset.forName("UTF-8");
        Path file = Paths.get("keys/" + name + ".pub.pem");
        BufferedReader reader = Files.newBufferedReader(file,charset);
        PEMReader parser = new PEMReader(reader);
        Object o = parser.readObject();
        //logger.debug(o.getClass()); 
        if (o instanceof JCERSAPublicKey) {
            return (JCERSAPublicKey) o;
        } else {
            logger.error("Wrong key type");
            return null;
        }
    }

    private PrivateKey readPrivateKey(String name) throws IOException {
        Charset charset = Charset.forName("UTF-8");
        Path file = Paths.get("keys/" + name + ".pem");
        BufferedReader reader = Files.newBufferedReader(file,charset);
        PEMReader parser = new PEMReader(reader, new UserPassword());
        Object o = parser.readObject();
        //logger.debug(o.getClass()); 
        if (o instanceof KeyPair) {
            return ((KeyPair) o).getPrivate();
        } else {
            logger.error("Wrong key type");
            return null;
        }
    }

    public IClientCli getCli() {
        return cli;
    }

    class UserPassword implements PasswordFinder {
        public char[] getPassword() {
            return pw.toCharArray(); 
        }
    }

    class ClientCli implements IClientCli {
        private Logger logger;

        public ClientCli() {
            logger = Logger.getLogger("Client.ClientCli");
        }

        @Command
        public Response l(String username, String password)
            throws IOException {
            return login(username, password);
        }
 
        @Command
        public Response login(String username, String password) throws IOException {
            pw = password;
            logger.debug("started pub/priv key login");
            logger.debug("username is " + username);
            
            // read user keys
            try {
                publicKey = readPublicKey(username);
                privateKey = readPrivateKey(username);
            } catch (IOException  ex) {
                logger.debug(ex.getMessage());
                return new MessageResponse("Couldn't read the keys for this " +
                                           "user.");
            }

            // create client challange
            SecureRandom random = new SecureRandom();
            byte[] cliCh = new byte[32];
            random.nextBytes(cliCh);
            byte[] cliCh64 = Base64.encode(cliCh);


            // stage1: login request, client challange
            if(!loginStage1(username, cliCh))
                return new MessageResponse("An Error occured.");

            // stage2: client challange response, proxy challange, aes params
            OkResponse okresp = loginStage2(cliCh);
            if (okresp == null)
                return new MessageResponse("An Error occured.");                

            // stage3: proxy challange response
            if(!loginStage3(okresp))
                return new MessageResponse("An Error occured.");

            // stage4: login
            Response resp = loginStage4();

            return resp;
        }

        /**
         * Stage1
         * The client sends a login request with a challange (random bits to
         * decrypt).
         * The message is encrypted with the proxys public key.
         */
        private boolean loginStage1(String username, byte[] cliCh) {
            SecureLoginRequest loginreq = 
                new SecureLoginRequest(username, cliCh);
            
            byte[] loginReqCipher;
            try {
                loginReqCipher = Cryptopus.encryptObject(loginreq, proxyPubKey);
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return false;
            }

            // send request (1st msg)
            SecureRequest req = new SecureRequest(loginReqCipher);
            try {
                oos.writeObject(req);
            } catch (IOException ex) {
                logger.debug(ex.getMessage());
                return false;
            }
            logger.debug("wrote secure login request to proxy");
            return true;
        }

        /**
         * Stage2
         * The client recieves the challange response from the proxy. Further
         * he gets his own challange from the proxy and the parameters for
         * the aes cipher to be used in future communication.
         */
        private OkResponse loginStage2(byte[] cliCh) {
            Response resp = null;
            logger.debug("Waiting for response");
            Object o;
            try {
                o = ois.readObject();
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return null;
            }
            if (o instanceof SecureResponse) {
                SecureResponse secresp = (SecureResponse) o;
                logger.debug("Got secure response.");
                    
                // decode response
                //byte[] secRespCipherB64 = secresp.getBytes();
                //byte[] secRespCipher = Base64.decode(secRespCipherB64);
                byte[] secRespCipher = secresp.getBytes();

                // decrypt response
                Object decrObj = null;
                try {
                    decrObj = 
                        Cryptopus.decryptObject(secRespCipher, privateKey);
                } catch (Exception ex) {
                    logger.debug(ex.getMessage()); 
                    return null;
                }
                if (decrObj instanceof OkResponse) {
                    // verify challange
                    OkResponse okresp = (OkResponse) decrObj;
                    byte[] cliChResp = okresp.getClientChallange();
                    if (Arrays.equals(cliCh, cliChResp)) {
                        logger.debug("Client challange won."); 
                        return okresp;
                    }
                    else {
                        logger.debug("Client challange failed.");
                    }
                }
            }
            return null;
        }

        /**
         * The client sends the proxy challange back for verification.
         */
        private boolean loginStage3(OkResponse okresp) {
            // create aes cipher
            try {
                aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
                // iv
                /*byte[] ivparam = 
                  Base64.decode(okresp.getIvParameter());*/
                byte[] ivparam = okresp.getIvParameter();
                IvParameterSpec spec = 
                    new IvParameterSpec(ivparam);

                // skey
                /*SecretKeySpec skey = new SecretKeySpec(
                  Base64.decode(okresp.getSecretKey()), "AES");*/
                SecretKeySpec skey = new SecretKeySpec(
                    okresp.getSecretKey(), "AES");

                // init cipher
                aesCipher.init(Cipher.ENCRYPT_MODE, skey, spec);

            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return false;
            }

            // decode proxy challange
            /*byte[] prxChB64 = okresp.getProxyChallange();
              byte[] prxCh = Base64.decode(prxChB64);*/
            byte[] prxCh = okresp.getProxyChallange();

            // encrypt proxy challange
            byte[] prxChCiph;
            try {
                prxChCiph = aesCipher.doFinal(prxCh);
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return false;
            }
            // encode proxy challange
            byte[] prxChCiphB64 = Base64.encode(prxChCiph);

            // send proxy challange response (3rd msg)
            SecureResponse prxChResp = 
                new SecureResponse(prxChCiph);
            logger.debug("Sending proxy challange.");
            try {
                oos.writeObject(prxChResp);
            } catch (IOException ex) {
                logger.debug(ex.getMessage());
                return false;
            }
            return true;
        }

        /**
         * The client waits for a final login response.
         */
        private Response loginStage4() {
            Object o;
            try {
                o = ois.readObject();
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return null;
            }
            if(o instanceof LoginResponse) {
                LoginResponse lresp = (LoginResponse) o;
                logger.debug(lresp.getType());
                if(lresp.getType() == LoginResponse.Type.SUCCESS) {
                    sid = lresp.getSid();
                    logger.debug("Got sid " + sid);
                } else if (lresp.getType() == 
                           LoginResponse.Type.WRONG_CREDENTIALS) {
                    logger.debug("Credentials are wrong.");
                } else if (lresp.getType() ==
                           LoginResponse.Type.IS_LOGGED_IN) {
                    logger.debug("Already logged in.");
                }
                return lresp;
            } 
            else if (o instanceof MessageResponse) {
                MessageResponse mresp = (MessageResponse) o;
                return mresp;
            }
            return null;
        }

        @Command
        public LoginResponse pwlogin(String username, String password)
            throws IOException {
            logger.debug("started login command");
            logger.debug("username is " + username);
            logger.debug("password is " + password);

            LoginRequest req = new LoginRequest(username, password);
            oos.writeObject(req);

            LoginResponse resp;
            try {
                Object o = ois.readObject();
                if(o instanceof LoginResponse) {
                    resp = (LoginResponse) o;
                    logger.debug(resp.getType());
                    if(resp.getType() == LoginResponse.Type.SUCCESS) {
                        sid = resp.getSid();
                        logger.debug("Got sid " + sid);
                    } else if (resp.getType() == 
                               LoginResponse.Type.WRONG_CREDENTIALS) {
                        logger.debug("Credentials are wrong.");
                    } else if (resp.getType() ==
                               LoginResponse.Type.IS_LOGGED_IN) {
                        logger.debug("Already logged in.");
                    }
                    return resp;
                }
                else {
                    logger.error("Login response corrupted.");
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
            return null;
        }

        @Command
        public Response c() throws IOException {
            return credits();
        }
 
        @Command
        public Response credits() throws IOException {
            CreditsRequest req = new CreditsRequest(sid);
            oos.writeObject(req);

            Response response = null;
            try {
                Object o = ois.readObject();
                if(o instanceof CreditsResponse) {
                    CreditsResponse cresp = (CreditsResponse) o;
                    response = new MessageResponse("You have " + 
                                                   cresp.getCredits() + 
                                                   " credits left.");
                }
                else if(o instanceof MessageResponse) {
                    response = (MessageResponse) o;
                    //logger.debug(response.toString());
                }
                else {
                    logger.error("Credits response corrupted.");
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
            return response;
        }

        @Command
        public Response buy(long credits) throws IOException {
            BuyRequest req = new BuyRequest(sid, credits);
            oos.writeObject(req);

            Response response = null;
            try {
                Object o = ois.readObject();
                if(o instanceof BuyResponse) {
                    BuyResponse bresp = (BuyResponse) o;
                    response = new MessageResponse("You now have " + 
                                                   bresp.getCredits() + 
                                                   " credits.");
                }
                else if(o instanceof MessageResponse) {
                    response = (MessageResponse) o;
                    //logger.debug(response.toString());
                }
                else {
                    logger.error("Credits response corrupted.");
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
            return response;

        }

        @Command
        public Response list() throws IOException {
            ListRequest req = new ListRequest(sid);
            oos.writeObject(req);

            Response resp = null;
            try {
                Object o = ois.readObject();
                if(o instanceof ListResponse) {
                    resp = (ListResponse) o;
                    //logger.debug(resp.toString());
                }
                else if(o instanceof MessageResponse) {
                    resp = (MessageResponse) o;
                }
                else {
                    logger.error("List response corrupted.");
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
            return resp;
        }

        @Command
        public Response d(String filename) throws IOException {
            return download(filename);
        }
 
        @Command
        public Response download(String filename) throws IOException {
            DownloadTicketRequest req = 
                new DownloadTicketRequest(sid, filename);
            oos.writeObject(req);


            // get download ticket
            DownloadTicket ticket = null;
            Response resp = null;
            try {
                Object o = ois.readObject();
                if(o instanceof DownloadTicketResponse) {
                    DownloadTicketResponse tresp = (DownloadTicketResponse) o;
                    ticket = tresp.getTicket();
                    //logger.debug(resp.toString());
                }
                else if(o instanceof MessageResponse) {
                    resp = (MessageResponse) o;
                }
                else {
                    logger.error("List response corrupted.");
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }

            // request download
            DownloadFileResponse dlresp = null;
            if(ticket != null) {
                String host = ticket.getAddress().getHostAddress();
                int port = ticket.getPort();
                DownloadFileRequest request = new DownloadFileRequest(ticket);
                FileServerConnection fscon = 
                    new FileServerConnection(host, port, request);
                Response response = fscon.call();
                if(response instanceof DownloadFileResponse) {
                    dlresp = (DownloadFileResponse) response;
                    byte[] content = dlresp.getContent();
                } 
                else if(response instanceof MessageResponse) {
                    return (MessageResponse) response;
                }
            }
            
            // save file
            if(dlresp != null && 
               filename.equals(dlresp.getTicket().getFilename())) {
                byte[] content = dlresp.getContent();
                File file = new File(downloadDir, filename);
                try {
                    if(file.exists()) {
                        file.delete();
                    }
                    file.createNewFile();
                    FileWriter fw = new FileWriter(file);
                    BufferedWriter bw = new BufferedWriter(fw);
                    fw.write(new String(content), 0, content.length);
                    bw.close();
                } catch (IOException x) {
                    logger.debug("Couldn't write file.");
                    x.printStackTrace();
                }
                resp = dlresp;
            }
            return resp;
        }

        @Command
        public Response u(String filename) throws IOException {
            return upload(filename);
        }
 
        @Command
        public MessageResponse upload(String filename) throws IOException {
            File file = new File(downloadDir, filename);
            String filestring = "";
            BufferedReader br;
            MessageResponse response = null;
            try {
                br = new BufferedReader(new FileReader(file));
                
                
                while(br.ready()) {
                    filestring = filestring + br.readLine();
                }
                byte[] content = filestring.getBytes();
                br.close();
                
                Request request = new UploadRequest(sid, filename, 1, content);
                oos.writeObject(request);

                try {
                    Object o = ois.readObject();
                    if(o instanceof MessageResponse) {
                        response = (MessageResponse) o;
                    } else {
                        response = new MessageResponse("Upload failed.");
                    }
                } catch (ClassNotFoundException x) {
                    logger.info("Class not found.");
                    x.printStackTrace();
                }
                
            } catch (FileNotFoundException x) {
                response = new MessageResponse("File does not exist.");
            } catch (IOException x) {
                logger.debug("Couldn't read file.");
                x.printStackTrace();
            }
            
            return response;
        }

        @Command
        public MessageResponse logout() throws IOException {
            LogoutRequest req = new LogoutRequest(sid);
            oos.writeObject(req);

            MessageResponse resp = null;
            try {
                Object o = ois.readObject();
                if(o instanceof MessageResponse) {
                    resp = (MessageResponse) o;
                    logger.debug(resp.toString());
                }
                else {
                    logger.error("Logout response corrupted.");
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
            return resp;
        }
    
        @Command
        public MessageResponse exit() throws IOException {
            logger.info("Exiting shell.");

            // clean up
            pool.shutdownNow();
            try {
                proxySocket.close();
            } catch (IOException x) {
                logger.info("Caught IOException.");
            }
            
            // close shell
            shell.close();

            // close System.in
            System.in.close();

            logger.info("Shutting down.");
            return new MessageResponse("Shutdown client.");
        }

        @Command
        public void muh() throws IOException {
            //logger.debug("muuuh");
            // proxy test
            String muh = new String("muuuh");
            oos.writeObject(muh);
            try {
                Object o = ois.readObject();
                if(o instanceof MessageResponse) {
                    MessageResponse mresp = (MessageResponse) o;
                    logger.info(mresp.getMessage());
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
        }
    }

}
