package proxy;

import java.util.*;
import java.util.regex.*;
import java.util.concurrent.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.net.*;
import java.rmi.RemoteException;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import cli.*;
import shared.IProxyManagementComponent;
import shared.PublicKeyRequest;
import shared.PublicKeyResponse;
import shared.ReadQuorumResponse;
import shared.SubscribeRequest;
import shared.SubscribeResponse;
import shared.TopThreeResponse;
import shared.WriteQuorumResponse;
import util.*;
import model.*;
import message.*;
import message.request.*;
import message.response.*;

import org.apache.log4j.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.openssl.*;
import org.bouncycastle.jce.provider.*;

/**
 * The Proxy
 */
public class Proxy {
    /**
     * member variables
     */
    // name of the server
    private String name;

    // stop signal
    private boolean stop = false;

    // logger
    private static Logger logger;
        {
            // set up logger
            logger = Logger.getLogger("Proxy");
            logger.setLevel(Level.DEBUG);
            BasicConfigurator.configure();
            logger.debug("Logger is set up.");
        }

    // a list of all users
    private ArrayList<User> users;

    // a list of all fileservers
    private ArrayList<FileServer> fileservers;

    // file server usage
    private Map<FileServer, Integer> fsUsage;

    // cached list of files on the the fileservers
    private Set<String> fileCache;

    // the proxy shell
    private Shell shell;

    // the proxy cli interface
    private IProxyCli cli;
    
    // the alive listener
    private KeepAliveListener keepAliveListener;

    // client connection listener 
    private ClientConnectionListener CCL;

    // client connection sockets
    private ArrayList<Socket> clientSockets = new ArrayList<Socket>();

    // the thread pool
    private ExecutorService pool;

    // object input stream
    private ObjectInputStream ois;

    // config
    private Config config;

    // proxy private key
    private PrivateKey privateKey;

    //* everything below is read from the config file *//

    // time interval after which a fileserver is set offline
    private Integer timeout;

    // period in ms to check for timeouts
    private Integer checkPeriod;

    // TCP port to listen for clients
    private Integer tcpPort;

    // UDP port to listen for keepAlive packages
    private Integer udpPort;

    // user keys dir
    private String keyDir;

    // proxy priv key dir
    private String privateKeyDir;

    /**
     * main function
     */
    public static void main(String[] args) {
        Proxy proxy = new Proxy("proxy");
        try {
            proxy.run();
        }
        catch (IOException x) {
            logger.info("Caught IOException");
        }
        return;
    }

    /**
     * Constructor
     */
    public Proxy(String name) {
        this.name = name;
        this.config = new Config(name);
        this.shell = new Shell(name, System.out, System.in);
    }

    public Proxy(String name, Config config, Shell shell) {
        this.name = name;
        this.config = config;
        this.shell = shell;
    }


    /**
     * Entry function for running the services
     */
    public void run() throws IOException {
        // make bouncy caslte provider default
        Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        Security.insertProviderAt(prov, 1);

        // read proxy config
        String key = name;
        try {
            key = "tcp.port";
            tcpPort = config.getInt(key);
            key = "udp.port";
            udpPort = config.getInt(key);
            key = "fileserver.timeout";
            timeout = config.getInt(key);
            key = "fileserver.checkPeriod";
            checkPeriod = config.getInt(key);
            key = "keys.dir";
            keyDir = config.getString(key) + "/";
            key = "key";
            privateKeyDir = config.getString(key);
        }
        catch (MissingResourceException x) {
            if(key == name) {
                logger.fatal("Config " + key + 
                             ".properties does not exist.");
            } else {
                logger.fatal("Key " + key + " is not defined.");
            }
            System.exit(1);
        }

        // create lists
        users = new ArrayList<User>();
        fileservers = new ArrayList<FileServer>();
        fsUsage = new HashMap<FileServer, Integer>();
        fileCache = new HashSet<String>();


        logger.info(name + " configured, starting services.");

        // read user config
        readUserConfig();

        // read private key
        try {
            privateKey = readPrivateKey(privateKeyDir);
        } catch (IOException ex) {
            logger.fatal("Couldn't read proxys private key.");
            logger.debug(ex.getMessage());
            System.exit(1);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        // create thread pool
        pool = Executors.newFixedThreadPool(30);

        // give birth to alive thread listener and start it
        keepAliveListener = new KeepAliveListener();
        logger.info("Starting to listen for keep alive messages.");
        pool.submit(keepAliveListener);

        // create client connection listener
        CCL = new ClientConnectionListener();
        logger.info("Starting to listen for client connections.");
        pool.submit(CCL);

        // create fileserver timout checker
        FileServerTimeoutChecker fstoc = new FileServerTimeoutChecker();
        logger.info("Starting to check for fileserver timeouts.");
        Timer timer = new Timer(true); // start as daemon
        timer.schedule(fstoc, 0, checkPeriod);

        // give birth to shell thread and start it
        cli = new ProxyCli();
        shell.register(cli);
        logger.info("Starting the shell.");
        Future shellfuture = pool.submit(shell);
        
        // Instantiate ProxyManagementHandler 
        ProxyManagementHandler proxyManagementHandler = new ProxyManagementHandler();  
        
        // starting registry
        RegistryHelper registryHelper = RegistryHelper.getInstance();
        registryHelper.startRegistry(proxyManagementHandler);

        System.out.println("Proxy started."); 
/*
// for now join shell
try {
shellfuture.get();
} catch (InterruptedException x) {
logger.info("Caught interrupt while waiting for shell.");
} catch (ExecutionException x) {
logger.info("Caught ExecutionExcpetion while waiting for shell.");
}
*/
        
        logger.info("Closing main");
    }

    public IProxyCli getCli() {
        return cli;
    }

    /**
     * Read user information from the config file.
     */
    private int readUserConfig() {
        HashSet<String> usernames = new HashSet<String>();

        // setup
        String filename = new String("user.properties");
        Path file = Paths.get("build/" + filename); 
        Charset charset = Charset.forName("UTF-8");

        // process file, read properties
        try(BufferedReader reader = Files.newBufferedReader(file,charset)){
                // create pattern to match property lines
                Pattern p = Pattern.compile("^[a-z0-9]*[.].*");

                // read file
                logger.info("Reading user config.");
                while(reader.ready()) {
                    String line = reader.readLine();
                    Matcher m = p.matcher(line);
                    
                    // extract properties and values
                    if(m.matches())
                    {
                        Scanner scanner = new Scanner(line);
                        String username = scanner.findInLine("^[a-zA-Z0-9]*");
                        usernames.add(username);
                    }

                }
            }
        catch (IOException x) {
            logger.info("IOException: %s%n", x);
        }

        // create user db
        Iterator<String> it = usernames.iterator();
        Config config = new Config("user");
        try{
            while(it.hasNext()) {
                String username = it.next();
                logger.info("Adding user " + username);
                users.add(new User(username,
                                   config.getString(username + ".password"),
                                   config.getInt(username + ".credits")));
                // debug
                //users.get(users.size() - 1).print();
            }
        }
        catch (Exception x) {
            logger.error("Your user config " +
                         "is corrupted. Make sure you have " +
                         "supplied all necessary variables.");
            return 1;
        }
        return 0;
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
        PEMReader parser = new PEMReader(reader, new ProxyPasswordFinder());
        Object o = parser.readObject();
        //logger.debug(o.getClass()); 
        if (o instanceof KeyPair) {
            return ((KeyPair) o).getPrivate();
        } else {
            logger.error("Wrong key type");
            return null;
        }
    }

    class ProxyPasswordFinder implements PasswordFinder {
        public char[] getPassword() {
            return "12345".toCharArray(); 
        }
    }

    private FileServer getCurrentFileserver() {
        // get first online fs
        FileServer lowest = null;
        for(FileServer fs : fileservers) {
            if(fs.isOnline()) { 
                lowest = fs; 
                break;
            }
        }
        
        if(lowest == null) {
            // no fileservers online
            return null;
        }

        // search for lowest usage fs
        for(FileServer fs : fileservers) {
            if(!fs.isOnline()) {continue;};
            if(lowest.getUsage() > fs.getUsage()) {
                lowest = fs;
            }
        }
            
        return lowest;
    }
            
    private class FileServerTimeoutChecker extends TimerTask {
        public void run() {
            Calendar cal = Calendar.getInstance();
            Date dateNow = cal.getTime();
            long now = dateNow.getTime();

            for(FileServer fs : fileservers) {
                long lastAlive = fs.getLastAlive().getTime();
                if(lastAlive + timeout < now) {
                    fs.setOffline();
                }
            }
        }
    }

    private class KeepAliveListener implements Runnable {
        /** 
         * Member variables
         */
        private DatagramSocket aliveSocket;

        /**
         * Constructor
         */
        public KeepAliveListener(){
            //logger = Logger.getLogger("Proxy.KeepAliveListener");
        }

        /**
         * run method
         */
        public void run() {
            // configure connection
            try {
                aliveSocket = new DatagramSocket(udpPort);
                byte[] buf = new byte[256];
                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                ByteBuffer wrapper;

                logger.info("Starting to listen for packets.");
                try{
                    while(true) {
                        try {
                            aliveSocket.receive(packet);
                            String data = new String(packet.getData()).trim();
                            Integer tcpPort = Integer.valueOf(data);
                            Integer port = packet.getPort();
                            String host = packet.getAddress().getHostAddress();
                            /*logger.info("Packet from " + host + ":" + port + 
                              " data: " + tcpPort);*/
                            updateFileServer(host, port, tcpPort);
                        } catch (NumberFormatException x) {
                            logger.info("Couldn't parse data.");
                        }
                    } 
                } catch (IOException x) {
                    logger.info("Interrupted. closing...");
                } 
            }
            catch (IOException x) {
                logger.info("IO Exception thrown.");
            } catch (Exception x) {
                x.printStackTrace();
            }
            if(aliveSocket != null)
                aliveSocket.close();
            logger.info("Shutting down alive listener.");
        }
        
        public DatagramSocket getAliveSocket() {
            return aliveSocket;
        }

        private void updateFileServer(String host, Integer port, 
                                      Integer tcpPort) {
            // if fs already present, set online and update timestamp
            for(FileServer f : fileservers) {
                if(f.getHost().equals(host) &&
                   f.getTcpPort().equals(tcpPort)) {
                    Calendar cal = Calendar.getInstance();
                    f.setLastAlive(cal.getTime());
                    f.setOnline();
                    return;
                }
            }

            // else add the fs
            logger.debug("Adding new file server: " + host + ":" + port + ":" +
                         tcpPort + ".");
            FileServer fs = new FileServer(host, port, tcpPort);
            fileservers.add(fs);
            fsUsage.put(fs,0);
            pool.submit(new UpdateFileCache(fs));
            return;
        }
    }

    private class ClientConnectionListener implements Runnable {
        //Logger logger;
        ServerSocket serverSocket;

        public ClientConnectionListener() {
            //logger = Logger.getLogger("Proxy.ClientConnectionListener");
        }

        /**
         * run method
         */
        public void run() {
            // start listening for connections
            logger.info("Creating server socket.");
            try {
                serverSocket = new ServerSocket(tcpPort);
            } 
            catch (IOException x) {
                logger.warn("Could not listen on port: " + tcpPort);
                return;
            }

            // accept connection
            try {
                logger.debug("Listening on port " + tcpPort + ".");
                for(int i = 1;; i = i+1) {
                    Socket clientSocket = serverSocket.accept();
                    logger.debug("Creating " + i + ". connection.");
                    ClientConnection con = new ClientConnection(clientSocket);
                    pool.submit(con);
                }
            } catch (IOException x) {
                logger.info("Interrupted. Stopping...");
            }

            // cleanup
            try {
                serverSocket.close();
            } catch (IOException x) {
                logger.info("Caught IOException on closing socket");
            }
            logger.info("Shutting down.");
        }

        public ServerSocket getServerSocket() {
            return serverSocket;
        }
    }


    private class ClientConnection implements Runnable, IProxy {
        /** 
         * member variables
         */
        private Socket clientSocket;
        //private Logger logger;
        private User user;
        private Channel channel;

        /** 
         * Constructor
         */
        public ClientConnection(Socket clientSocket) {
            this.clientSocket = clientSocket;
            clientSockets.add(clientSocket);
            //logger = Logger.getLogger("Proxy.ClientConnection");
        }

        /**
         * run method
         */
        public void run() {
            logger.debug(clientSocket.toString());
            try {
                // create streams
                ObjectInputStream ois = 
                    new ObjectInputStream(clientSocket.getInputStream());
                ObjectOutputStream oos = 
                    new ObjectOutputStream(clientSocket.getOutputStream());

                channel = new TCPChannel(ois, oos);
                Response response = null;

                // listen for requests
                while(!Thread.interrupted()) {
                    // recieve request
                    //Object o = ois.readObject();
                    Object o = channel.read();
                    
                    // SECURE REQUEST
                    if(o instanceof SecureRequest) {
                        logger.debug("Got secure request.");
                        SecureRequest request = (SecureRequest) o;
                        byte[] reqCipher = request.getBytes();
                        Object reqObj;
                        try {
                            reqObj = 
                                Cryptopus.decryptObject(reqCipher, privateKey);
                            // forward decrypted request
                            o = reqObj;
                        } catch (Exception ex) {
                            logger.debug(ex.getMessage());
                            response = new MessageResponse("Request failed.");;
                        }
                    }

                    // LOGIN
                    if(o instanceof LoginRequest) {
                        logger.debug("Got login request.");
                        LoginRequest request = (LoginRequest) o;
                        response = login(request);
                    }
                    // SECURE LOGIN
                    else if(o instanceof SecureLoginRequest) {
                        logger.debug("Got secure login reqeust");
                        SecureLoginRequest request = (SecureLoginRequest) o;
                        response = secureLogin(request);
                    }
                    // CREDITS
                    else if (o instanceof CreditsRequest) {
                        logger.debug("Got credits request.");
                        CreditsRequest request = (CreditsRequest) o;
                        // verify request
                        response = verify(request.getSid());
                        if(response == null) {
                            response = credits();                        
                        } 
                    }
                    // BUY
                    else if (o instanceof BuyRequest) {
                        logger.debug("Got buy request.");
                        BuyRequest request = (BuyRequest) o;
                        // verify request
                        response = verify(request.getSid());
                        if(response == null) {
                            response = buy(request);
                        }
                    }
                    // LIST
                    else if (o instanceof ListRequest) {
                        logger.debug("Got list request.");
                        ListRequest request = (ListRequest) o;
                        // verify reqeust
                        response = verify(request.getSid()); 
                        if(response == null) {
                            response = list();
                        }
                    }
                    // DOWNLOAD
                    else if (o instanceof DownloadTicketRequest) {
                        logger.debug("Got download request.");
                        DownloadTicketRequest request = 
                            (DownloadTicketRequest) o;
                        // verify reqeust
                        response = verify(request.getSid()); 
                        if(response == null) {
                            response = download(request);
                        }
                    }
                    // UPLOAD
                    else if (o instanceof UploadRequest) {
                        logger.debug("Got upload request.");
                        UploadRequest request = (UploadRequest) o;
                        // verify reqeust
                        response = verify(request.getSid()); 
                        if(response == null) {
                            response = upload(request);
                        }
                    }
                    // LOGOUT
                    else if (o instanceof LogoutRequest) {
                        logger.debug("Got logout request.");
                        LogoutRequest request = (LogoutRequest) o;
                        // verify request
                        response = verify(request.getSid());
                        if(response == null) {
                            response = logout();
                        } 
                    }
                    // TESTING REQUEST; cow says muh!!
                    else if (o instanceof String) {
                        if(user == null || user.getSid() == null) {
                            response = new MessageResponse("Ur not logged in.");
                        } else {
                            response = new MessageResponse("Ur in.");
                        }
                    }
                    
                    // send response back
                    if(response != null) {
                        //oos.writeObject(response);
                        channel.write(response);
                        if (o instanceof LogoutRequest) {
                            // revert to unencrypted channel
                            logger.debug("Degrading to unencrypted channel."); 
                            channel = channel.degrade();
                        }
                    } else {
                        String msg = "Dwarfes attacked us, we were defenseless!";
                        //oos.writeObject(new MessageResponse(msg));
                        channel.write(new MessageResponse(msg));
                    }
                }
            } catch (IOException x) {
                logger.info("Caught IOException.");
            } catch (Exception x) {
                logger.info("Caught Exception: "); 
                x.printStackTrace();
            } finally {
                try {
                    logger.debug("Closing socket.");
                    clientSocket.close();
                } catch (IOException x) {
                    logger.info("Caught IOException.");
                }
            }
            // clean seassion
            try {
                logout();
            } catch (IOException x) {
                logger.info("Caught IOException.");
            }
        }

        private User getUserBySid(UUID sid) {
            for(User u : users) {
                if(u.getSid() == sid) {
                    return u;
                }
            }
            return null;
        }

        private MessageResponse verify(UUID sid) {
            if(user == null) {
                return new MessageResponse("You are not logged in.");
            } else if (!user.getSid().equals(sid)) {
                return new MessageResponse("Did you tamper with the IDs? " +
                                           "Go play somewhere else.");
            } else {
                return null;
            }
        }

        private boolean checkSid(UUID sid) {
            if(user != null && user.getSid().equals(sid)) {
                return true;
            } else {
                return false;
            }
        }                
        
        private Response secureLogin(SecureLoginRequest request) {
            Response failedResp = new MessageResponse("Could not log in.");
            SecureLoginRequest req = request;
            //-- MESSAGE 1 --//            
            // implicit

            //-- MESSAGE 2 --//

            // get user pub key
            String username = req.getUsername();
            PublicKey userPubKey;
            try {
                userPubKey = readPublicKey(keyDir + username + ".pub.pem");
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return failedResp;
            }
            
            // craft ok response
            logger.debug("Crafting response."); 
            
            // client challenge
            /*byte[] clChB64 = req.getClientChallenge();
              byte[] clCh = Base64.decode(clChB64);*/
            byte[] clCh = req.getClientChallenge();
            
            SecureRandom random = new SecureRandom();
            
            // proxy challenge
            byte[] proxyChallenge = new byte[32];
            random.nextBytes(proxyChallenge);
            byte[] proxyChallengeB64 = Base64.encode(proxyChallenge);
            
            // secret aes key
            KeyGenerator kgen;
            try {
                kgen = KeyGenerator.getInstance("AES");
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return failedResp;
            }
            kgen.init(256);
            SecretKey skey = kgen.generateKey();
            byte[] skeybytes = skey.getEncoded();
            byte[] skeybytesB64 = Base64.encode(skeybytes);
            
            // initialization vector
            byte[] ivparam = new byte[16];
            random.nextBytes(ivparam);
            byte[] ivparamB64 = Base64.encode(ivparam);
            
            // craft response
            OkResponse okresp = new OkResponse(clCh, 
                                               proxyChallenge,
                                               skeybytes, ivparam);
            
            // encrypt response
            byte[] respCipher;
            logger.debug("Encrypting response.");
            try {
                respCipher = Cryptopus.encryptObject(okresp, userPubKey);   
            } catch (Exception ex) {
                logger.debug(ex.getMessage()); 
                return failedResp;
            }
            
            // encode response
            byte[] respCipherB64 = Base64.encode(respCipher);
            
            // send response
            SecureResponse resp = new SecureResponse(respCipher);
            logger.debug("Sending secure response back."); 
            try {
                //oos.writeObject(resp);
                channel.write(resp);
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return failedResp;
            }
            
            //-- MESSAGE 3 --//

            // create cipher
            Cipher aesCipher; 
            IvParameterSpec spec; 
            try {
                aesCipher = Cipher.getInstance("AES/CTR/NoPadding");
                spec = new IvParameterSpec(ivparam);
                aesCipher.init(Cipher.DECRYPT_MODE, skey, spec);
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return failedResp;
            }
            
            // read proxy challenge response from client
            logger.debug("Waiting for challenge response.");
            Object prxChObj;
            try {
                //prxChObj = ois.readObject();
                prxChObj = channel.read();
            } catch (Exception ex) {
                logger.debug(ex.getMessage());
                return failedResp;
            }
            if (prxChObj instanceof SecureResponse) {
                logger.debug("Got challenge response."); 
                SecureResponse prxChResp = (SecureResponse) prxChObj;
                
                // decode proxy challenge
                /*byte[] prxChCipherB64 = prxChResp.getBytes();
                  byte[] prxChCipher = Base64.decode(prxChCipherB64);*/
                byte[] prxChCipher = prxChResp.getBytes();
                
                // decrypt proxy challenge
                byte[] prxChPlain;
                try {
                    prxChPlain = aesCipher.doFinal(prxChCipher);
                } catch (Exception ex) {
                    logger.debug(ex.getMessage());
                    logger.error("Couldn't decrypt proxy challenge.");
                    return failedResp;
                }
                
                // verify proxy challenge
                if(Arrays.equals(prxChPlain, proxyChallenge)) {
                    logger.debug("Proxy challenge won.");

                    // switch to secure channel
                    logger.debug("Switching to secure channel."); 
                    channel = new SecureChannel(channel, skey, spec);

                    //-- MESSAGE 4 --//
                    loginUser(username);
                    if (user != null) {
                        user.setSecretKey(skey);
                        user.setSpec(spec);
                        return new LoginResponse(
                            LoginResponse.Type.SUCCESS, user.getSid());
                    }
                    
                }
                else {
                    logger.debug("Proxy challenge failed."); 
                }
                
            } else {
                logger.debug("That's not the expected class :/");
                logger.debug(prxChObj.getClass()); 
            }
            return failedResp;
        }
        
        
        private void loginUser(String username) {
            // try to log in
            logger.debug("Logging in user: " + username);
            for(User u : users) {
                // search matching user
                if(u.getName().equals(username)) {
                    if(u.login()) {
                        // successfull
                        // create new session id
                        UUID sid = UUID.randomUUID();
                        u.setSid(sid);
                        
                        // set user for this connection
                        user = u;
                    } 
                }
            }
        }

        @Override
        public LoginResponse login(LoginRequest request) throws IOException {
            LoginResponse response = null;

            // client is logged in with a user
            if(user != null) {
                response = new LoginResponse
                    (LoginResponse.Type.IS_LOGGED_IN);
            } 
            // try to log in
            else {
                logger.debug("Got login request: " + request.getUsername()
                             + ":" + request.getPassword());
                for(User u : users) {
                    // search matching user
                    if(u.getName().equals(request.getUsername()) &&
                       u.getPassword().equals(request.getPassword())) {
                        if(u.login()) {
                            // successfull
                            // create new session id
                            UUID sid = UUID.randomUUID();
                            u.setSid(sid);

                            // set user for this connection
                            user = u;

                            // craft response
                            response = new LoginResponse(
                                LoginResponse.Type.SUCCESS, sid); 
                        } 
                    }
                }
                if(response == null) {
                    // no user found or wrong creds
                    response = new LoginResponse(
                        LoginResponse.Type.WRONG_CREDENTIALS);
                }
            }
            return response;
        }

        @Override
        public Response credits() throws IOException {
            return new CreditsResponse(user.getCredits());
        }

        @Override
        public Response buy(BuyRequest request) throws IOException {
            long newCredits = user.getCredits() + request.getCredits();
            user.setCredits(newCredits);
            return new BuyResponse(newCredits);
        }

        @Override
        public Response list() throws IOException {
            return new ListResponse(fileCache);
        }

        @Override
        public Response download(DownloadTicketRequest request) throws IOException {
            String filename;
            long filesize;
            int version;

            // get file size
            Request inforequest = new InfoRequest(request.getFilename());
            FileServer fs = getCurrentFileserver();
            if(fs == null) {
                return new MessageResponse("No file server available.");
            }

            FileServerConnection fscon = new 
                FileServerConnection(fs.getHost(), fs.getTcpPort(), inforequest);
            Object o = fscon.call();
            if(o instanceof InfoResponse) {
                InfoResponse response = (InfoResponse) o;
                filesize = response.getSize();
                filename = response.getFilename();
                logger.debug("File " + filename + " has size " + filesize);
            } 
            else if (o instanceof MessageResponse) {
                return (Response) o;
            } else {
                logger.error("Response corrupted.");
                return null;
            }
  
            // get file version
            Request versionrequest = new VersionRequest(request.getFilename());
            fscon = new FileServerConnection(fs.getHost(), fs.getTcpPort(), 
                                             versionrequest);
            o = fscon.call();
            if(o instanceof VersionResponse) {
                VersionResponse response = (VersionResponse) o;
                version = response.getVersion();
                if (!filename.equals(response.getFilename())) {
                    logger.error("Version request on different filename.");
                    return null;
                }
                logger.debug("File " + filename + " is version " + version);
            } 
            else if (o instanceof MessageResponse) {
                return (MessageResponse) o;
            } else {
                logger.error("Response corrupted.");
                return null;
            }


            // check if user has enough credits
            if(user != null && user.getCredits() >= filesize) {
                // decrease user credits
                user.setCredits(user.getCredits() - filesize);
                // increase fs usage
                fs.setUsage(fs.getUsage() + filesize);

                // craft download ticket
                String checksum = 
                    ChecksumUtils.generateChecksum(user.getName(), filename,
                                                   version, filesize);
                InetAddress host = InetAddress.getByName(fs.getHost());
                DownloadTicket ticket = 
                    new DownloadTicket(user.getName(), filename, checksum,
                                       host,fs.getTcpPort());
                
                // send desired response
                return new DownloadTicketResponse(ticket);
                
            } else {
                return new MessageResponse("Not enough credits.");
            }
        }

        @Override
        public MessageResponse upload(UploadRequest request) throws IOException {
            FileServerConnection fscon;
            for(FileServer f : fileservers) {
                fscon = new FileServerConnection(f.getHost(), f.getTcpPort(),
                                                 request);
                Response response = fscon.call();
            }

            // increase user credits
            user.setCredits(user.getCredits() + 2 * request.getContent().length);
            
            // add file to file cache
            fileCache.add(request.getFilename());
            return new MessageResponse("success");
        }

        @Override
        public MessageResponse logout() throws IOException {
            if(user != null) {
                logger.debug("Logging out user " + user.getName() +
                             ".");
                user.logout();
                user = null;
            }
            return new MessageResponse("Successfully logged out.");
        }
        
    }

    class UpdateFileCache implements Runnable {
        Logger logger;
        FileServer fs;

        public UpdateFileCache(FileServer fs) {
            logger = Logger.getLogger("Proxy.UpdateFileCache");
            this.fs = fs;
        }

        public void run() {
            logger.debug("Updating file cache. New file server is " + 
                         fs.getHost() + ":" + fs.getTcpPort() + ".");
            Request request = new ListRequest(null);
            FileServerConnection fscon = new FileServerConnection
                (fs.getHost(), fs.getTcpPort(), request);
            
            Object o = fscon.call();
            if(o instanceof ListResponse) {
                ListResponse response = (ListResponse) o;
                fileCache.addAll(response.getFileNames());
                logger.debug("File cache updated.");
            } else {
                logger.debug("Coudln't get filelist.");
            }
        }
    }

    class ProxyCli implements IProxyCli {
        private Logger logger;

        public ProxyCli() {
            logger = Logger.getLogger("Proxy.ProxyCli");
        }

        @Command
        public Response fileservers() throws IOException {
            // create fileserver info array
            ArrayList<FileServerInfo> fsInfos = new ArrayList<FileServerInfo>();
            for(FileServer fs : fileservers) {
                InetAddress addr = InetAddress.getByName(fs.getHost());
                fsInfos.add(new FileServerInfo(addr, fs.getPort(), fs.getUsage(),
                                               fs.isOnline()));
            }

            // send response
            return new FileServerInfoResponse(fsInfos);
        }

        @Command
        public Response users() throws IOException {
            ArrayList<UserInfo> uinfo = new ArrayList<UserInfo>();
            for(User u : users) {
                uinfo.add(new UserInfo(u.getName(), u.getCredits(), u.isLoggedIn()));
            }
            return new UserInfoResponse(uinfo);
        }

        @Command
        public MessageResponse exit() throws IOException {
            logger.info("Exiting shell.");

            // clean up
            pool.shutdownNow();

            DatagramSocket aliveSocket = keepAliveListener.getAliveSocket();
            if(aliveSocket != null) {
                logger.debug("Closing alive socket.");
                aliveSocket.close(); // throws io exc in alive listener
            }
            ServerSocket serverSocket = CCL.getServerSocket();
            if(serverSocket != null) {
                logger.debug("Closing server socket.");
                serverSocket.close(); // throws io exc in ccl
            }            
 
            for (Socket s : clientSockets) {
                if (s != null) {
                    logger.debug("closing client connection");
                    s.close(); // throws io exc in client sockets
                }
            }

            // close System.in (blocking)
            System.in.close();
 
            // close shell 
            shell.close();
            
            logger.info("Shutting down.");
            return new MessageResponse("Shutdown proxy.");
        }

        @Command
        public void muh() throws IOException {
            System.out.println("muuuhhh");
        }

    }
    
    public class ProxyManagementHandler implements IProxyManagementComponent {

        @Override
        public ReadQuorumResponse getReadQuorum() {
            // TODO Auto-generated method stub
            logger.debug("getReadQuorum");
            return null;
        }

        @Override
        public WriteQuorumResponse getWriteQuorum() {
            // TODO Auto-generated method stub
            logger.debug("getWriteQuorum");
            return null;
        }

        @Override
        public TopThreeResponse getTopThree() {
            // TODO Auto-generated method stub
            logger.debug("getTopThree");
            return null;
        }

        @Override
        public SubscribeResponse subscribe(SubscribeRequest subscribeRequest) {
            // TODO Auto-generated method stub
            logger.debug("subscribe");
            return null;
        }

        @Override
        public PublicKeyResponse getPublicKey() {
            // TODO Auto-generated method stub
            logger.debug("getPublicKey");
            return null;
        }

        @Override
        public void sendPublicKey(PublicKeyRequest publicKeyRequest) {
            // TODO Auto-generated method stub
            logger.debug("setPublicKey");
            
        }
        
    }
}