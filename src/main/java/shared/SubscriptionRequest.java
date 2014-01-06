package shared;

import java.io.Serializable;

public class SubscriptionRequest implements Serializable {


    /**
     * 
     */
    private static final long serialVersionUID = 5600370775943136389L;
    
    private String filename;

    private int numberOfDownloads;

    private String username;

    private ISubscriptionListener subscriptionListener;
    
    public SubscriptionRequest(String username, String filename, int numberOfDownloads, ISubscriptionListener subscriptionListener) {
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
