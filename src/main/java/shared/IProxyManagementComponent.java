package shared;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IProxyManagementComponent extends Remote {
    
    ReadQuorumResponse getReadQuorum() throws RemoteException;
    
    WriteQuorumResponse getWriteQuorum() throws RemoteException;
    
    TopThreeResponse getTopThree() throws RemoteException;
    
    SubscribeResponse subscribe(SubscribeRequest subscribeRequest) throws RemoteException;
    
    PublicKeyResponse getPublicKey() throws RemoteException;
    
    void sendPublicKey(PublicKeyRequest publicKeyRequest) throws RemoteException;
    
    
    

}
