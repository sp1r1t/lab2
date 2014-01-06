package shared;

import java.io.Serializable;

/**
 * Contains the notification message from the proxy to the subscriber-client
 * @author Martin
 *
 */
public class SubscriptionNotification implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -3630156942217387041L;
    
    public final String message;
    
    public SubscriptionNotification(String message) {
        this.message = message;
    }
    
    public SubscriptionNotification(String filename, int numberOfDownloads) {
        this.message = "Notification: " + filename + " got downloaded " + numberOfDownloads + " times!.";
    }
    

}
