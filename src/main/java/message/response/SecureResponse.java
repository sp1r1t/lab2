package message.response;

import message.Response;

/**
 * 
 * <p/>
 * <b>Request</b>:<br/>
 * 
 * <b>Response:</b><br/>
 * 
 * 
 */
public class SecureResponse implements Response {
    private static final long serialVersionUID = 8589241886679930421L;

    private byte[] bytes;

    public SecureResponse(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public String toString() {
        return new String(getBytes());
    }
}
