package shared;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.Map;

public interface IProxyManagementComponent extends Remote {
    
    Integer getReadQuorum() throws RemoteException;
    
    Integer getWriteQuorum() throws RemoteException;
    
    Map<String, Integer> getTopThree() throws RemoteException;
    
    Boolean subscribe(SubscriptionRequest subscribeRequest) throws RemoteException;
    
    PublicKeyResponse getPublicKey() throws RemoteException;
    
    Boolean sendPublicKey(PublicKeyRequest publicKeyRequest) throws RemoteException;
    
    
    

}
