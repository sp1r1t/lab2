package shared;

import java.rmi.RemoteException;

import message.response.MessageResponse;

public interface IClientRMICommands {
    
    MessageResponse readQuorum() throws RemoteException;
    
    MessageResponse writeQuorum() throws RemoteException;
    
    MessageResponse topThreeDownloads() throws RemoteException;
    
    MessageResponse subscribe(String filename, int numberOfDownloads) throws RemoteException;
    
    MessageResponse getProxyPublicKey() throws RemoteException;
    
    MessageResponse setUserPublicKey(String userName) throws RemoteException;

}
