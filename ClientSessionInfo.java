/*
 * ClientSessionInfo.java
 * 
 * @Date: Mar 22, 2014
 *
 * @Note:
 *
 * This class maintains the client information during the session,
 * which is used by client
 *  
 */

//package IMClient;

import java.net.InetAddress;

public class ClientSessionInfo {
	public ClientSessionInfo(String name, InetAddress address, int port) {
		this.name = name;
		this.IPAddress = address;
		this.port = port;
		this.DHPublicKey = null;
		this.DHSessionKey = null;
	}

	public String toString() {
		return "ClientSessionInfo [name= " + name +
				", IPAddress= " + IPAddress +
				", port= " + port + "]";
	}

	public byte[] getDHPublicKey() {
		return this.DHPublicKey;
	}

	public void setDHPublicKey(byte[] key) {
        // Validate key size
        if (key != null) {
            if (key.length == KEY_SIZE) {
                this.DHPublicKey = key;
            }
            else {
                System.out.println("SetDHPublicKey - Invalid key size");
            }
        }
        else {
            this.DHPublicKey = null;
        }

	}

	public byte[] getDHSessionKey() {
		return this.DHSessionKey;
	}
	
	public void setDHSessionKey(byte[] key) {
        // Validate key size
        if (key != null) {
            if (key.length == KEY_SIZE) {
                this.DHSessionKey = key;
            }
            else {
                System.out.println("SetDHSessionKey - Invalid key size");
            }
        }
        else {
            this.DHSessionKey = null;
        }

	}

	/* basic info */
	private String name;
	private InetAddress IPAddress;
	private int port;

    // Server info
    private byte[] serverID;

	/* key info */
	private byte[] DHPublicKey;
	private byte[] DHSessionKey;

    public static final int KEY_SIZE = 128;
	
	// TODO specifications of the key
	
	
}
