package message.request;

import message.Request;

/**
 * Encasulates a request for integrity checking
 */
public class HmacRequest implements Request {
    private static final long serialVersionUID = -37629665574053670L;

    private Request request;
    private byte[] hash; 
    
    public HmacRequest(Request req, byte[] hash) {
        request = req;
        this.hash = hash;
    }

    public byte[] getHash() {
        return hash;
    }
    
    public Request getRequest() {
        return request;
    }

    @Override
    public String toString() {
        return "!hmacrequest";
    }
}
