package message.request;

import message.Request;

/**
 * Authenticates the client with the provided username and client challenge.
 * <p/>
 * <b>Request</b>:<br/>
 * {@code !login &lt;username&gt; &lt;password&gt;}<br/>
 * <b>Response:</b><br/>
 * {@code !login success}<br/>
 * or<br/>
 * {@code !login wrong_credentials}
 *
 * @see message.response.LoginResponse
 */
public class SecureLoginRequest implements Request {
    private static final long serialVersionUID = -1596776158259072949L;

    private final String username;
    private final byte[] clientChallenge;

    public SecureLoginRequest(String username, byte[] clientChallenge) {
        this.username = username;
        this.clientChallenge = clientChallenge;
    }

    public String getUsername() {
        return username;
    }

    public byte[] getClientChallenge() {
        return clientChallenge;
    }

    @Override
    public String toString() {
        return String.format("!login %s %s", getUsername(), getClientChallenge());
    }
}