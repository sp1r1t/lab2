package proxy;

import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import proxy.Proxy.ProxyManagementHandler;
import shared.IProxyManagementComponent;
import util.Config;

/**
 * Helps setting up the registry
 * @author Martin
 *
 */
public class RegistryHelper {

    // logger
    private static Logger logger;
    {
        // set up logger
        logger = Logger.getLogger("RegistryHelper");
        logger.setLevel(Level.DEBUG);
        BasicConfigurator.configure();
    }

    private static RegistryHelper instance = null;
    
    private static final String PROPERTYFILENAME = "mc";

    // config data
    private String bindingName;
    private String proxyHost;
    private int proxyRmiPort;
    private String keysDir;

    private RegistryHelper() {
        Config config = new Config(PROPERTYFILENAME);
        
        bindingName = config.getString("binding.name");
        proxyHost = config.getString("proxy.host");
        proxyRmiPort = config.getInt("proxy.rmi.port");
        keysDir = config.getString("keys.dir");
    }
    
    /**
     * Binds registry to the defined port
     */
    public void startRegistry(ProxyManagementHandler proxyManagementHandler) {
        // try to find existing registry
//        try {
//            // try to get existing registry
//            Registry registry = LocateRegistry.getRegistry(proxyHost, proxyRmiPort);
//            registry.list(); // force actual connection to registry
//            logger.debug("Existing registry found");
//            return;
//        } catch (ConnectException e)  {
//            logger.warn("Finding registry failed: not found, creating new one");
//        } catch (RemoteException e) {
//            logger.warn("Finding registry failed: RemoteException", e);
//        }
        
        // create new registry
        try {
            logger.debug("Creating new registry");
            IProxyManagementComponent stub = (IProxyManagementComponent) UnicastRemoteObject.exportObject(proxyManagementHandler, 0);
            Registry registry = LocateRegistry.createRegistry(proxyRmiPort);
            registry.bind(bindingName, stub);
        } catch (RemoteException e) {
            logger.error("Creating registry failed (RemoteException)", e);
        } catch (AlreadyBoundException e) {
            logger.error("Creating registry failed (AlreadyBoundException)", e);
        }
    }

    public static synchronized RegistryHelper getInstance() {
        if (instance == null)
            instance = new RegistryHelper();
        return instance;
    }


}
