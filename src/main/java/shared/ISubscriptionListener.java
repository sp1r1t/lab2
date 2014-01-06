package shared;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface ISubscriptionListener extends Remote {
    
    void notifySubscriber(SubscriptionNotification subscriptionNotification) throws RemoteException;

}
