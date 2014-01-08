package proxy;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.ArrayList;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import shared.SubscriptionNotification;
import shared.SubscriptionRequest;

/**
 * Handles file subscriptions
 * 
 * @author Martin
 * 
 */
public class SubscriptionHandler {

    // logger
    private Logger logger;
    {
        // set up logger
        logger = Logger.getLogger("SubscriptionHandler");
        BasicConfigurator.configure();
        logger.setLevel(Level.DEBUG);
        logger.debug("Logger is set up.");
    }

    private ArrayList<Subscription> list = new ArrayList<Subscription>();

    /**
     * Proxy notifies if a file download occured
     * 
     * @param filename
     */
    public void notifyFileDownload(String filename) {
        // check whether file is subscribed
        for (Subscription s : list) {
            if (s.subscriptionRequest.getFilename().equals(filename)) {
                // count up download
                s.downloadCounter++;
                // if max is reached send callback notification
                if (s.subscriptionRequest.getNumberOfDownloads() == s.downloadCounter) {
                    try {
                        s.subscriptionRequest.getSubscriptionListener().notifySubscriber(
                                new SubscriptionNotification(filename, s.downloadCounter));
                    } catch (RemoteException e) {
                        logger.error("Callback failed", e);
                    } catch (IOException e) {
                        logger.error("Callback failed", e);
                    }
                    // reset counter
                    s.downloadCounter = 0;
                }
            }
        }
    }

    public void addSubscription(SubscriptionRequest subscriptionRequest) {
        list.add(new Subscription(subscriptionRequest));
    }

    public void removeSubscription(String username) {
        Subscription toRemove = null;
        for (Subscription s : list) {
            if (s.subscriptionRequest.getUsername().equals(username)) {
                //list.remove(s);
                toRemove = s;
                break;
            }
        }
        if (toRemove != null) {
            list.remove(toRemove);
        }

    }

    public void removeAllSubscriptions() {
        list.clear();
    }

    /**
     * Manages single subscription
     * 
     * @author Martin
     * 
     */
    class Subscription {
        final SubscriptionRequest subscriptionRequest;
        int downloadCounter = 0;

        public Subscription(SubscriptionRequest subscriptionRequest) {
            this.subscriptionRequest = subscriptionRequest;
        }

    }

}
