package server;

import java.util.*;
import java.util.regex.*;
import java.util.concurrent.*;
import java.io.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.net.*;

import cli.*;
import util.*;
import message.*;
import message.request.*;
import message.response.*;
import model.*;

import org.apache.log4j.*;

/**
 * The Server
 */
public class FileServer {
    /**
     * private variables
     */
    // name of the server
    private String name;

    // the thread pool
    protected ExecutorService pool;

    // logger
    private static Logger logger;
    {
        // set up logger
        logger = Logger.getLogger("FileServer");
        BasicConfigurator.configure();
        logger.setLevel(Level.FATAL);
        logger.debug("Logger is set up.");
    }

    // the fileserver shell
    private Shell shell;

    // the fileserver cli
    private IFileServerCli cli;

    // proxy connection listener
    private ProxyConnectionListener PCL;

    // config
    private Config config;

    // version map
    private HashMap<String,Integer> version = new HashMap<String,Integer>();


    // everything below is read from the config file

    // time interval to send alive packets
    private int alivePeriod;

    // file directory identifier
    private String dirString;

    // file directory
    private File dir;

    // TCP port to listen for clients
    private int tcpPort;

    // address of the proxy
    private String proxy;

    // UDP port of the proxy to send alive packets to
    private int udpPort;

    /**
     * main function
     */
    public static void main(String[] args) {
        String name = new String(args[0]);
        FileServer fs = new FileServer(name);
        try {
            logger.info(name + " configured, starting services.");
            fs.run();
        }
        catch (IOException x) {
            logger.info("Ex: Caught IOException");
        }
        return;
    }

    /**
     * Constructor
     */
    public FileServer(String name) {
        this.name = name;
        this.config = new Config(name);
        this.shell = new Shell(name, System.out, System.in);
    }

    public FileServer(String name, Config config, Shell shell) {
        this.name = name;
        this.config = config;
        this.shell = shell;
    }


    /**
     * Entry function for running the services
     */
    public void run() throws IOException {
        // read config
        String key = name;
        try {
            key = "fileserver.alive";
            alivePeriod = config.getInt(key);
            key = "fileserver.dir";
            dirString = config.getString(key);
            key = "tcp.port";
            tcpPort = config.getInt(key);
            key = "proxy.host";
            proxy = config.getString(key);
            key = "proxy.udp.port";
            udpPort = config.getInt(key);
        } catch (MissingResourceException x) {
            if(key == name) {
                logger.fatal("Config " + key + 
                             ".properties does not exist.");
            } else {
                logger.fatal("Key " + key + " is not defined.");
            }
            System.exit(1);
        }
        
        // set up file directory
        dir = new File(dirString);
        if(!dir.exists()) {
            logger.warn("Specified directory does not exist. Creating it.");
            dir.mkdirs();
        }
        logger.debug("File list: ");
        for(String s : dir.list()) {
            // init version to 0
            version.put(s,0);
            logger.debug(s);
        }
        
        // create executor service
        pool = Executors.newFixedThreadPool(10);

        // start ProxyConnectionListener
        logger.info("Starting ProxyConnectionListener");
        PCL = new ProxyConnectionListener();
        pool.submit(PCL);

        // start shell
        logger.info("Starting the shell.");
        cli = new FileServerCli();
        shell.register(cli);
        Future shellfuture = pool.submit(shell);


        // start thread to send keep alive msgs
        logger.info("Starting KeepAlive");
        KeepAlive keepAlive = new KeepAlive(udpPort, proxy, alivePeriod, tcpPort);
        pool.submit(keepAlive);

        System.out.println("FileServer started.");

        // for now just join the shell. the main thread is kept alive to 
        // possibly implement respawning of unintenionally cancelled threads 
        // in the future.
        // e.g. if the keepAlive thread fails due to network problems this can
        // be handled here. or other maintainance stuff that may come.
        /*
        try {
            shellfuture.get();
        } catch (InterruptedException x) {
            logger.info("Caught interrupt while waiting for shell.");
        } catch (ExecutionException x) {
            logger.info("Caught ExecutionExcpetion while waiting for shell.");
            }*/

        logger.info("Closing main");
    }

    public IFileServerCli getCli() {
        return cli;
    }

    /**
     * Read variables from the config file.
     * The file needs to be named <name>.properties
     */
    private int readConfigFile() {
        HashMap<String,String> properties = new HashMap<String,String>();

        // setup
        String filename = new String(name + ".properties");
        Path file = Paths.get("build/" + filename); 
        Charset charset = Charset.forName("UTF-8");

        // process file, read properties
        try(BufferedReader reader = Files.newBufferedReader(file,charset)){
                // create pattern to match property lines
                Pattern p = Pattern.compile("^[a-z0-9.]*=[a-zA-Z0-9/]*");

                // read file
                logger.info("Reading config for " + name + ".");
                while(reader.ready()) {
                    String line = reader.readLine();
                    Matcher m = p.matcher(line);
                    
                    // extract properties and values
                    if(m.matches())
                    {
                        Scanner scanner = new Scanner(line).useDelimiter("=");
                        String property = scanner.next();
                        String value = scanner.next();
                        properties.put(property,value);
                        logger.info("  " + property + " = " +
                            value);
                    }

                }
            }
        catch (IOException x) {
            System.err.format("FileServer::readConfigFile: IOException: %s%n", x);
        }

        // save properties
        try{
            alivePeriod = Integer.parseInt(properties.get("fileserver.alive"));
            dirString = properties.get("fileserver.dir");
            tcpPort = Integer.parseInt(properties.get("tcp.port"));
            proxy = properties.get("proxy.host");
            udpPort = Integer.parseInt(properties.get("proxy.udp.port"));
        }
        catch (Exception x) {
            logger.error("Your config file for the server " +
                               name + " is corrupted. Make sure you have " +
                               "supplied all necessary variables.");
            return 1;
        }
        return 0;
    }

    private boolean testFileExists(String filename) {
        Path path = Paths.get(dirString,filename);
        return Files.exists(path);
    }

    private boolean testEnoughCredits(String filename, int credits) {
        try {
            Path path = Paths.get(dirString,filename);
            return (credits >= Files.size(path));
        }
        catch (IOException x){
            logger.info("IOException caught");
            return false;
        }
    }

    private class KeepAlive implements Runnable {
        /**
         * member variables
         */
        // logger
        private Logger logger;

        // udp socket for alive packages
        private DatagramSocket aliveSocket;

        // config params
        private int udpPort;
        private String proxy;
        private int alivePeriod;
        private int tcpPort;

        /**
         * Constructor
         */
        public KeepAlive(int udpPort, String proxy, 
                               int alivePeriod, int tcpPort){
            // init logger
            logger = Logger.getLogger("FileServer.KeepAlive");

            // init params
            this.udpPort = udpPort;
            this.proxy = proxy;
            this.alivePeriod = alivePeriod;
            this.tcpPort = tcpPort;
        }

        /**
         * run method
         */
        public void run() {
            try {
                // configure connection
                aliveSocket = new DatagramSocket();
                
                String msg = new String(String.valueOf(tcpPort));
                byte[] buf = msg.getBytes();

                InetAddress address = InetAddress.getByName(proxy);
                
                DatagramPacket packet = 
                    new DatagramPacket(buf, buf.length, address, udpPort); 
                
                try {
                    // send keep alive      
                    logger.debug("Starting to send keep alive messages...");
                    while(true){
                        aliveSocket.send(packet);
                        Thread.sleep(alivePeriod);
                    }
                } catch (InterruptedException x) {
                    logger.info("Recieved interrupt. Closing...");
                }

                // close aliveSocket
                aliveSocket.close();
            }
            catch (IOException x) {
                logger.info("IO Exception thrown.");
            }
        }

    }

    private class ProxyConnectionListener implements Runnable {
        Logger logger;
        ServerSocket serverSocket;

        public ProxyConnectionListener() {
            logger = Logger.getLogger("FileServer.ProxyConnectionListener");
        }

        /**
         * run method
         */
        public void run() {
            // start listening for connections
            logger.info("Creating server socket on port " + tcpPort + ".");
            try {
                serverSocket = new ServerSocket(tcpPort);
            } 
            catch (IOException x) {
                logger.warn("Could not listen on port: " + tcpPort);
                return;
            }

            // accept connection
            try {
                for(int i = 1;; i = i+1) {
                    logger.debug("Waiting for " + i + ". client on " + tcpPort +
                                 ".");
                
                    Socket clientSocket = serverSocket.accept();
                    logger.debug("Accepted Connection.");
                    ProxyConnection con = new ProxyConnection(clientSocket);
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

    private class ProxyConnection implements Runnable {
        /** 
         * member variables
         */
        Socket clientSocket;
        Logger logger;

        /** 
         * Constructor
         */
        public ProxyConnection(Socket clientSocket) {
            this.clientSocket = clientSocket;
            logger = Logger.getLogger("FileServer.ProxyConnection");
        }

        /**
         * run method
         */
        public void run() {
            logger.info("Starting Connection.");
            try {
                // create streams
                ObjectInputStream ois = 
                    new ObjectInputStream(clientSocket.getInputStream());
                ObjectOutputStream oos = 
                    new ObjectOutputStream(clientSocket.getOutputStream());

                
                Response response = null;

                // recieve request
                Object o = ois.readObject();
                if(o instanceof ListRequest) {
                    logger.debug("Got list requeest.");

                    // create file set
                    Set<String> fileset = new HashSet<String>();
                    for(String s : dir.list()) {
                        fileset.add(s);
                    }
                    response = new ListResponse(fileset);
                } 
                else if(o instanceof InfoRequest) {
                    logger.debug("Got info request.");
                    InfoRequest request = (InfoRequest) o;
                    String filename = request.getFilename();

                    // create file set
                    Set<String> fileset = new HashSet<String>();
                    for(String s : dir.list()) {
                        fileset.add(s);
                    }
                    if(fileset.contains(filename)) {
                        File file = new File(dirString,filename);
                        long size = file.length();
                        response = new InfoResponse(filename, size);
                    } else {
                        logger.debug("File not found.");
                        response = new MessageResponse("File not found.");
                    }
                }
                else if(o instanceof VersionRequest) {
                    logger.debug("Got version request.");
                    VersionRequest request = (VersionRequest) o;
                    String filename = request.getFilename();

                    // create file set
                    Set<String> fileset = new HashSet<String>();
                    for(String s : dir.list()) {
                        fileset.add(s);
                    }
                    if(fileset.contains(filename)) {
                        File file = new File(dirString,filename);
                        response = new VersionResponse(filename, version.get(filename));
                    } else {
                        logger.debug("File not found.");
                        response = new MessageResponse("File not found.");
                    }
                }
                else if(o instanceof DownloadFileRequest) {
                    logger.debug("Got download request.");
                    DownloadFileRequest request = (DownloadFileRequest) o;
                    DownloadTicket ticket = request.getTicket();

                    // validate ticket
                    String user = ticket.getUsername();
                    String filename = ticket.getFilename();
                    String checksum = ticket.getChecksum();
                    InetAddress address = ticket.getAddress();
                    int port = ticket.getPort();
                    int version = 1;

                    File file = new File(dirString, filename);
                    if(ChecksumUtils.verifyChecksum
                       (user, file, version, checksum)) {
                        String filestring = "";
                        BufferedReader br;
                        try {
                            br = new BufferedReader(new FileReader(file));
                            
                            
                            while(br.ready()) {
                                filestring = filestring + br.readLine();
                            }
                            byte[] content = filestring.getBytes();
                            response = new DownloadFileResponse(ticket,
                                                                content);
                            br.close();
                        } catch (FileNotFoundException x) {
                            response = new MessageResponse("File does not " +
                                                           "exist.");
                        } 
                    }
                    // ticket invalid
                    else {
                        response = new MessageResponse("Checksum corrupted.");
                    }                    
                }
                else if(o instanceof UploadRequest) {
                    logger.debug("Got upload request.");
                    UploadRequest request = (UploadRequest) o;
                    String filename = request.getFilename();

                    // save file
                    byte[] content = request.getContent();
                    File file = new File(dirString, filename);
                    try {
                        if(file.exists()) {
                            file.delete();
                        }
                        file.createNewFile();
                        FileWriter fw = new FileWriter(file);
                        BufferedWriter bw = new BufferedWriter(fw);
                        fw.write(new String(content), 0, content.length);
                        bw.close();
                        // update version
                        Integer v = version.get(filename);
                        if (v == null) {
                            version.put(filename,1);
                        } else {
                            version.put(filename,++v);
                        }

                    } catch (IOException x) {
                        logger.debug("Couldn't write file.");
                        x.printStackTrace();
                    }
                }
                else {
                    logger.debug("Got bad request.");
                }

                // send response back
                oos.writeObject(response);
                
            } catch (IOException x) {
                logger.info("Caught IOException.");
            } catch (ClassNotFoundException x) {
                logger.info("Class not found.");
            } catch (IllegalArgumentException x) {
                //oos.writeObject(new MessageRespones("Illegal Argument"));
            }finally {
                try {
                    clientSocket.close();
                } catch (IOException x) {
                    logger.info("Caught IOException while closing socket.");
                }
            }
            
            logger.info("Closed connection.");
        }
    }

    class FileServerCli implements IFileServerCli {
        private Logger logger;
        
        public FileServerCli() {
            logger = Logger.getLogger("FileServer.FileServerCli");
        }

        @Command
        public MessageResponse exit() throws IOException {
            logger.info("Exiting shell.");

            // clean up threads
            pool.shutdownNow();
            ServerSocket serverSocket = PCL.getServerSocket();
            if(serverSocket != null)
                serverSocket.close(); // throws io exc in proxy con listener
            
            // close Syste.in (blocking)
            System.in.close();
            
            // close shell
            shell.close();
            
            logger.debug("Shutting down fileserver.");
            return new MessageResponse("Shutdown fileserver.");
        }

        @Command
        public void muh() throws IOException {
            System.out.println("muuuhhh");
        }
    }
}