package shared;

import java.rmi.RemoteException;

import message.response.MessageResponse;

public interface IClientRMICommands {
    
    MessageResponse readquorum();
    
    MessageResponse writequorum();
    
    MessageResponse topthree();
    
    MessageResponse subscribe(String filename);
    
    MessageResponse getpublickey();
    
    MessageResponse sendpublickey();

}
