package proxy;

import message.Response;
import message.Request;
import message.request.*;
import message.response.*;

import model.DownloadTicket;
import model.UserInfo;

import java.util.Date;
import java.util.Calendar;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Callable;
import java.util.UUID;
import java.util.Timer;
import java.util.TimerTask;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.InputStream;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.charset.Charset;
import java.nio.ByteBuffer;

import java.net.*;

import cli.Command;
import cli.Shell;

import util.Config;
import util.ChecksumUtils;
import util.FileServerConnection;

import model.FileServerInfo;

import proxy.User;
import proxy.FileServer;

import org.apache.log4j.Logger;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;

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

    // the thread pool
    private ExecutorService pool;

    // object input stream
    private ObjectInputStream ois;

    private InputStream in;

    //* everything below is read from the config file *//

    // time interval after which a fileserver is set offline
    private Integer timeout;

    // period in ms to check for timeouts
    private Integer checkPeriod;

    // TCP port to listen for clients
    private Integer tcpPort;

    // UDP port to listen for keepAlive packages
    private Integer udpPort;

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
        // set name
        this.name = name;

        in = System.in;

        // set up logger
        logger = Logger.getLogger(Proxy.class);
        BasicConfigurator.configure();
        //logger.setLevel(Level.toLevel("FATAL"));
        logger.debug("Logger is set up.");

        // read config
        String key = name;
        try {
            Config config = new Config(key);
            key = "tcp.port";
            tcpPort = config.getInt(key);
            key = "udp.port";
            udpPort = config.getInt(key);
            key = "fileserver.timeout";
            timeout = config.getInt(key);
            key = "fileserver.checkPeriod";
            checkPeriod = config.getInt(key);
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
        
        this.shell = null;
    }

    public Proxy(String name, Config config, Shell shell) {
        // set name
        this.name = name;
        
        in = null;

        // set up logger
        logger = Logger.getLogger(Proxy.class);
        BasicConfigurator.configure();
        logger.debug("Logger is set up.");

        // read config
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

        this.shell = shell;

        logger.info(name + " configured, starting services.");
    }


    /**
     * Entry function for running the services
     */
    public void run() throws IOException {
        // read user config
        readUserConfig();

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
        if(shell == null) {
            logger.debug("Creating new shell.");
            shell = new Shell(name, System.out, System.in);
        }
        shell.register(cli);
        logger.info("Starting the shell.");
        Future shellfuture = pool.submit(shell);


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
                users.get(users.size() - 1).print();
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
        private Logger logger;
        private DatagramSocket aliveSocket;

        /**
         * Constructor
         */
        public KeepAliveListener(){
            logger = Logger.getLogger(KeepAliveListener.class);
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
        Logger logger;
        ServerSocket serverSocket;

        public ClientConnectionListener() {
            logger = Logger.getLogger(ClientConnectionListener.class);
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
        private Logger logger;
        private User user;

        /** 
         * Constructor
         */
        public ClientConnection(Socket clientSocket) {
            this.clientSocket = clientSocket;
            logger = Logger.getLogger(ClientConnection.class);
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

                
                Response response = null;

                // listen for requests
                while(!Thread.interrupted()) {
                    // recieve request
                    Object o = ois.readObject();
                    
                    // LOGIN
                    if(o instanceof LoginRequest) {
                        logger.debug("Got login request.");
                        LoginRequest request = (LoginRequest) o;
                        response = login(request);
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
                        oos.writeObject(response);
                    } else {
                        String msg = "Dwarfes attacked us, we were defenseless!";
                        oos.writeObject(new MessageResponse(msg));
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
            return new MessageResponse("Uploaded.");
        }

        @Override
        public MessageResponse logout() throws IOException {
            if(user != null) {
                logger.debug("Logging out user " + user.getName() +
                             ".");
                user.logout();
                user = null;
            }
            return new MessageResponse("Logged out.");
        }
        
    }

    class UpdateFileCache implements Runnable {
        Logger logger;
        FileServer fs;

        public UpdateFileCache(FileServer fs) {
            logger = Logger.getLogger(UpdateFileCache.class);
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
            logger = Logger.getLogger(ProxyCli.class);
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
 
            // close System.in (blocking)
            if(in == System.in)
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
}