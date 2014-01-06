package message.response;

import message.Response;

/**
 * 
 * <p/>
 * <b>Request</b>:<br/>
 * 
 * <b>Response:</b><br/>
 * 
 * or<br/>
 * 
 *
 * 
 */
public class OkResponse implements Response {
    private static final long serialVersionUID = 3134831924072311109L;

    byte[] clientChallenge;
    byte[] proxyChallenge;
    byte[] secretKey;
    byte[] ivParameter;

    public OkResponse(byte[] clientChallenge, byte[] proxyChallenge, 
                      byte[] secretKey, byte[] ivParameter) {
        this.clientChallenge = clientChallenge;
        this.proxyChallenge = proxyChallenge;
        this.secretKey = secretKey;
        this.ivParameter = ivParameter;
    }

    public byte[] getClientChallenge() {
        return clientChallenge;
    }

    public byte[] getProxyChallenge() {
        return proxyChallenge;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public byte[] getIvParameter() {
        return ivParameter;
    }

    @Override
    public String toString() {
        return "!ok " + clientChallenge + " " + proxyChallenge + " " + 
            secretKey + " " + ivParameter;
    }
}
