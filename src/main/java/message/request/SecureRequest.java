package message.request;

import message.Request;

/**
 * 
 * <p/>
 * <b>Request</b>:<br/>
 * 
 * <b>Response:</b><br/>
 * 
 * 
 */
public class SecureRequest implements Request {
    private static final long serialVersionUID = 8589241766679930421L;

    private byte[] bytes;

    public SecureRequest(byte[] bytes) {
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
