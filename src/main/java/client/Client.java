package client;

import java.util.*;
import java.util.concurrent.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.net.*;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import cli.*;
import shared.IClientRMICommands;
import shared.IProxyManagementComponent;
import util.*;
import message.*;
import message.request.*;
import message.response.*;
import model.*;

import org.apache.log4j.*;
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

    // key dir
    private String keyDir;

    // proxy pubblic key dir
    private String proxyPubKeyDir;

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
    private Cipher aesCipher = null;

    // communication channel
    private Channel channel;

    // RMI Interface (Proxy stub)
    private IProxyManagementComponent proxyManagementComponent;
    
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
            key = "keys.dir";
            keyDir = config.getString(key) + "/";
            key = "proxy.key";
            proxyPubKeyDir = config.getString(key);
        } catch (MissingResourceException x) {
            if(key == name) {
                logger.fatal("Config " + key + 
                             ".properties does not exist.");
            } else {
                logger.fatal("Key " + key + " is not defined.");
            }
            System.exit(1);
        }
        
        // read rmi config
        Config rmiConfig = new Config("mc");
        String proxyHost = rmiConfig.getString("proxy.host");
        int proxyRmiPort = rmiConfig.getInt("proxy.rmi.port");
        String bindingName = rmiConfig.getString("binding.name");
        
        // init registry
        try {
            Registry registry = LocateRegistry.getRegistry(proxyHost, proxyRmiPort);
            proxyManagementComponent = (IProxyManagementComponent) registry.lookup(bindingName); 
        } catch (RemoteException e) {
            logger.error("Failed locating registry", e);
        } catch (NotBoundException e) {
            logger.error("Failed looking up binding name", e);
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
            proxyPubKey = readPublicKey(proxyPubKeyDir);
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

        channel = new TCPChannel(ois, oos);

        // set up shell
        cli = new ClientCli();
        shell.register(cli);
        logger.info("Starting the shell.");
        Future shellfuture = pool.submit(shell);

        logger.info("Client started.");

        /*
        // for now join shell
        try {
        shellfuture.get();
        } catch (InterruptedException x) {
        logger.info("Caught interrupt while waiting for shell.");
        } catch (ExecutionException x) {
        logger.info("Caught ExecutionExcpetion while waiting for shell.");
        } */

        //logger.info("Closing main.");
    }

    private PublicKey readPublicKey(String name) throws IOException {
        Charset charset = Charset.forName("UTF-8");
        Path file = Paths.get(name);
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
        Path file = Paths.get(name);
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

    class ClientCli implements IClientCli, IClientRMICommands {
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
                publicKey = readPublicKey(keyDir + username + ".pub.pem");
                privateKey = readPrivateKey(keyDir + username + ".pem");
            } catch (IOException  ex) {
                logger.debug(ex.getMessage());
                return new MessageResponse("Couldn't read the keys for this " +
                                           "user.");
            }

            // create client challenge
            SecureRandom random = new SecureRandom();
            byte[] cliCh = new byte[32];
            random.nextBytes(cliCh);
            byte[] cliCh64 = Base64.encode(cliCh);


            // message 1: login request, client challenge
            if(!loginMessage1(username, cliCh))
                return new MessageResponse("An Error occured.");

            // message 2: client challenge response, proxy challenge, aes params
            OkResponse okresp = loginMessage2(cliCh);
            if (okresp == null)
                return new MessageResponse("An Error occured.");                

            // message 3: proxy challenge response
            if(!loginMessage3(okresp))
                return new MessageResponse("An Error occured.");

            // message 4: login
            Response resp = loginMessage4();

            return resp;
        }

        /**
         * Message 1
         * The client sends a login request with a challenge (random bits to
         * decrypt).
         * The message is encrypted with the proxys public key.
         */
        private boolean loginMessage1(String username, byte[] cliCh) {
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
                //oos.writeObject(req);
                channel.write(req);
            } catch (IOException ex) {
                logger.debug(ex.getMessage());
                return false;
            }
            logger.debug("wrote secure login request to proxy");
            return true;
        }

        /**
         * Message2
         * The client recieves the challenge response from the proxy. Further
         * he gets his own challenge from the proxy and the parameters for
         * the aes cipher to be used in future communication.
         */
        private OkResponse loginMessage2(byte[] cliCh) {
            Response resp = null;
            logger.debug("Waiting for response");
            Object o;
            try {
                //o = ois.readObject();
                o = channel.read();
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
                    // verify challenge
                    OkResponse okresp = (OkResponse) decrObj;
                    byte[] cliChResp = okresp.getClientChallenge();
                    if (Arrays.equals(cliCh, cliChResp)) {
                        logger.debug("Client challenge won."); 
                        return okresp;
                    }
                    else {
                        logger.debug("Client challenge failed.");
                    }
                }
            }
            return null;
        }

        /**
         * Message 3
         * The client sends the proxy challenge back for verification.
         */
        private boolean loginMessage3(OkResponse okresp) {
            Channel secchannel;
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

                // create secure channel
                secchannel = new SecureChannel(channel, skey, spec);
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return false;
            }

            // decode proxy challenge
            /*byte[] prxChB64 = okresp.getProxyChallenge();
              byte[] prxCh = Base64.decode(prxChB64);*/
            byte[] prxCh = okresp.getProxyChallenge();

            // encrypt proxy challenge
            byte[] prxChCiph;
            try {
                prxChCiph = aesCipher.doFinal(prxCh);
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return false;
            }
            // encode proxy challenge
            byte[] prxChCiphB64 = Base64.encode(prxChCiph);

            // send proxy challenge response (3rd msg)
            //MessageResponse prxChResp = new MessageResponse(prChCiphB64);
            SecureResponse prxChResp = 
              new SecureResponse(prxChCiph);
            logger.debug("Sending proxy challenge.");
            try {
                //oos.writeObject(prxChResp);
                channel.write(prxChResp);
            } catch (IOException ex) {
                logger.debug(ex.getMessage());
                return false;
            }

            // set secure channel
            logger.debug("Switching to secure channel."); 
            channel = secchannel;
            return true;
        }

        /**
         * Message 4:
         * The client waits for a final login response.
         */
        private Response loginMessage4() {
            Object o;
            try {
                //o = ois.readObject();
                o = channel.read();
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
            //oos.writeObject(req);
            channel.write(req);

            LoginResponse resp;
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
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
            //oos.writeObject(req);
            channel.write(req);

            Response response = null;
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
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
            //oos.writeObject(req);
            channel.write(req);

            Response response = null;
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
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
            //oos.writeObject(req);
            channel.write(req);

            Response resp = null;
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
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
            //oos.writeObject(req);
            channel.write(req);


            // get download ticket
            DownloadTicket ticket = null;
            Response resp = null;
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
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
                //oos.writeObject(request);
                channel.write(request);

                try {
                    //Object o = ois.readObject();
                    Object o = channel.read();
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
            //oos.writeObject(req);
            channel.write(req);

            MessageResponse resp = null;
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
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

            // revert to unencrypted channel
            aesCipher = null;
            logger.debug("Degrading to unencrypted channel."); 
            channel = channel.degrade();
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
            //oos.writeObject(muh);
            channel.write(muh);
            try {
                //Object o = ois.readObject();
                Object o = channel.read();
                if(o instanceof MessageResponse) {
                    MessageResponse mresp = (MessageResponse) o;
                    logger.info(mresp.getMessage());
                }
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            }
        }

        @Override
        @Command
        public MessageResponse readquorum() {
            // TODO Auto-generated method stub
            logger.debug("readquorum client");
            try {
                proxyManagementComponent.getReadQuorum();
            } catch (RemoteException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return null;
        }

        @Override
        @Command
        public MessageResponse writequorum() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        @Command
        public MessageResponse topthree() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        @Command
        public MessageResponse subscribe(String filename) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        @Command
        public MessageResponse getpublickey() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        @Command
        public MessageResponse sendpublickey() {
            // TODO Auto-generated method stub
            return null;
        }
    }

}
