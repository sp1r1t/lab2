package shared;

import java.io.Serializable;

/**
 * Contains all data which is required for a subscription request
 * @author Martin
 *
 */
public class SubscriptionRequest implements Serializable {


    /**
     * 
     */
    private static final long serialVersionUID = 5600370775943136389L;
    
    private final String filename;

    private final int numberOfDownloads;

    private final String username;

    private final ISubscriptionListener subscriptionListener;
    
    public SubscriptionRequest(String username, String filename, 
                               int numberOfDownloads, 
                               ISubscriptionListener subscriptionListener) {
        this.username = username;
        this.filename = filename;
        this.numberOfDownloads = numberOfDownloads;
        this.subscriptionListener = subscriptionListener;
    }

    public String getUsername() {
        return username;
    }

    public String getFilename() {
        return filename;
    }

    public int getNumberOfDownloads() {
        return numberOfDownloads;
    }

    public ISubscriptionListener getSubscriptionListener() {
        return subscriptionListener;
    }
    
    
    
}
