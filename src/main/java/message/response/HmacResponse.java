package message.response;

import message.Response;

/**
 * Encasulates a response for integrity checking
 */
public class HmacResponse implements Response {
    private static final long serialVersionUID = -37629665574053670L;

    private Response response;
    private byte[] hash; 
    
    public HmacResponse(Response req, byte[] hash) {
        response = req;
        this.hash = hash;
    }

    public byte[] getHash() {
        return hash;
    }
    
    public Response getResponse() {
        return response;
    }

    @Override
    public String toString() {
        return "!hmacresponse";
    }
}
