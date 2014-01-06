package shared;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.Map;

import javax.naming.AuthenticationException;

/**
 * RMI Interface
 * @author Martin
 *
 */
public interface IProxyManagementComponent extends Remote {
    
    /**
     * This command returns the number of Read-Quorums that are currently used for the replication mechanism.
     * @return
     * @throws RemoteException
     */
    Integer getReadQuorum() throws RemoteException;
    
    /**
     * This command returns the number of Write-Quorums that are currently used for the replication mechanism. 
     * @return
     * @throws RemoteException
     */
    Integer getWriteQuorum() throws RemoteException;
    
    /**
     * This command retrieves a sorted list that contains the 3 files that got downloaded the most. Where the first file in the list, represents the file that got downloaded the most.
     * @return
     * @throws RemoteException
     */
    Map<String, Integer> getTopThree() throws RemoteException;
    
    /**
     * When using this command the user creates a subscription for the given file, which means that the user gets notified by the Proxy whenever the file gets downloaded the given number of times. Together with the parameters, the client should also send its remote object as a callback object for the Proxy. Without the callback object, the Proxy has no possibility to notify the client.
     * @param subscribeRequest
     * @throws RemoteException
     * @throws AuthenticationException
     * @throws FileNotFoundException
     */
    void subscribe(SubscriptionRequest subscribeRequest) throws RemoteException, AuthenticationException, FileNotFoundException;
    
    /**
     * A User can use this command to retrieve the Proxy's public key. When invoking this command the Proxy sends it's public key and the client stores the key in the key folder (given keys.dir property).
     * @return
     * @throws RemoteException
     */
    PublicKey getPublicKey() throws RemoteException;
    
    /**
     * With this command the user can exchange it's own public key with the Proxy. Therefore additionally to the name, the client should also send the public key for the given name. The Proxy stores the received key in the key folder (given keys.dir property).
     * @param userName
     * @param publicKey TODO
     * @return
     * @throws RemoteException
     * @throws IOException 
     */
    Boolean sendPublicKey(String userName, PublicKey publicKey) throws RemoteException;
    
    
    

}
