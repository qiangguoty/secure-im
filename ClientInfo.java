/*
 * ClientInfo.java
 * 
 * @author  Jingdi Ren
 * @since   Mar 23, 2014
 * @notes
 */

//package IMClient;

import java.net.*;
import java.util.regex.*;

public class ClientInfo {
    public ClientInfo() {
        this.name = null;
        
        try {
        	this.IPAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
        	this.IPAddress = null;
        }
        
        this.port = 0;
        this.permission = PERMISSION_USER;
        this.RSAPublicKey = null;
        this.isAuthenticated = false;
        this.consecutiveFailNumber = 0;
    }

    public byte[] getEncryptKey() {
    	return this.encryptKey;
    }
    
    public InetAddress getIPAddress() {
    	return this.IPAddress;
    }
    
    public int getPort() {
        return this.port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setChallenge(String challenge) {
    }

    private void loginAttempt() {
        this.consecutiveFailNumber++;
    }

    public boolean isFinished() {
        loginAttempt();
        return !((this.isAuthenticated == true) ||
                (this.consecutiveFailNumber >= MAX_FAILURE_NUM));

    }

    public boolean isAuthenticated() {
        return true;
    }

    public void setLoginAttemptSessionKey(byte[] key) {
    	this.loginAttemptSessionKey = key;
    }
    
    public byte[] getLoginAttemptSessionKey() {
    	return this.loginAttemptSessionKey;
    }
    public void setLoginSessionKey(byte[] key) {
    	this.loginAttemptSessionKey = key;
    }
    
    public byte[] getLoginSessionKey() {
    	return this.loginSessionKey;
    }
    public void setMessageSessionKey(byte[] key) {
    	this.messageSessionKey = key;
    }
    
    public byte[] getMessageSessionKey() {
    	return this.messageSessionKey;
    }
   
    public byte[] getRSAPublicKey() {
        return this.RSAPublicKey;
    }

    public void setRSAPublicKey(byte[] key) {
    	this.RSAPublicKey = key;
    }

    public byte[] getRSAPrivateKey() {
        return this.RSAPrivateKey;
    }

    public void setRSAPrivateKey(byte[] key) {
    	this.RSAPrivateKey = key;
    }
    
    public Pattern[] getCommandsPatterns() {
        if (this.permission == PERMISSION_SUPER) {
            return superCommandPatterns;
        }
        return userCommandPatterns;
    }

    private final static Pattern[] userCommandPatterns = { Pattern.compile("list"), 
                                                           Pattern.compile("send (.*) (.*)"),
                                                           Pattern.compile("exit")};

    private final static Pattern[] superCommandPatterns = { Pattern.compile("list"), 
                                                            Pattern.compile("send (.*) (.*)"),
                                                            Pattern.compile("history"),
                                                            Pattern.compile("serverinfo"),
                                                            Pattern.compile("attack"), // DoS
                                                            Pattern.compile("exit")};
    // permission bit
    private byte permission;

	public byte[] loginAttemptSessionKey;
	public byte[] loginSessionKey;
	public byte[] messageSessionKey;
	
	public byte[] loginDHNumber;
	public byte[] loginDHEncryptKey;

	public byte[] clientChallenge;
	public byte[] clientAnsser;

	public byte[] serverAnswer;
	
	public byte[] encryptKey;
	public byte[] RSAPublicKey;
	public byte[] RSAPrivateKey;

	public byte[] serverSessionTicket;
	public byte[] clientSessionTicket;
	
	public String name;

	private InetAddress IPAddress;
	private int port;

    private boolean isAuthenticated;
    private int consecutiveFailNumber;

    private static final byte MAX_FAILURE_NUM = 5;
    private static final byte PERMISSION_SUPER = 0x1;
    private static final byte PERMISSION_USER = 0x2;
}
