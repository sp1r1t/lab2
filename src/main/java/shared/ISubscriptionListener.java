package shared;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Required for RMI client callback
 * @author Martin
 *
 */
public interface ISubscriptionListener extends Remote {
    
    /**
     * Notifies the subscriber (client) about a certain event
     * @param subscriptionNotification
     * @throws RemoteException
     * @throws IOException
     */
    void notifySubscriber(SubscriptionNotification subscriptionNotification) throws RemoteException, IOException;

}
