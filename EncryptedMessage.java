/* 
 * EncryptedMessage.java
 *
 * @Date: 2014, March 22
 * 
 * @Note: This is the main class to encrypt the message
 * 
 * IM | Version | Type | EncryptedField
 * 01      2       3          4+
 *
 */
//package IMUtil;

import java.net.InetAddress;

public class EncryptedMessage {

    // TODO check the rawMessage size whether it is less than MAX_MSG_SIZE
    public EncryptedMessage(InetAddress dstIPAddress, int dstPort, byte[] bytes) {
    	this.dstIPAddress = dstIPAddress;
    	this.dstPort = dstPort;

    	if ((bytes[0] == MSG_HEADER[0]) && (bytes[1] == MSG_HEADER[1])) {
    		this.version = bytes[2];
    		this.type = bytes[3];
    		this.length = (bytes[4] << 8) + (bytes[5] & 0xFF);
    		this.message = new byte[this.length];
            System.arraycopy(bytes, MSG_HEADER_OFFSET, this.message, 0, this.length);
    	}
    }
    
	public EncryptedMessage(InetAddress dstIPAddress, int dstPort,
							 byte type, byte[] message) {
        this.dstIPAddress = dstIPAddress;
        this.dstPort = dstPort;
    	this.version = MSG_VER_1;
        this.type = type;
       
        if (message == null) {
        	message = new byte[0];
        	this.length = 0;
        }
        // only copy the bytes less than the MAX_MSG_SIZE
        if (message.length < MAX_FIELD_SIZE) {
        	this.message = message;
        	this.length = message.length;
        } else {
        	this.message = new byte[MAX_FIELD_SIZE];
        	this.length = MAX_FIELD_SIZE;
        	System.arraycopy(message, 0, this.message, 0, MAX_FIELD_SIZE);
        }
	}

	public boolean removeEncryptKey() {
		this.encryptKey = null;
		return true;
	}
	
	public boolean removeSessionTicket() {
		this.sessionTicket = null;
		return true;
	}
	
	public boolean setEncryptKey(byte[] key) {
		
		this.encryptKey = key;
		return true;
	}
	
	public boolean setSessionTicket(byte[] ticket) {
		this.sessionTicket = ticket;
		return true;
	}
	
	public InetAddress getDstIPAddress() {
		return this.dstIPAddress;
	}
	
	public int getDstPort() {
		return this.dstPort;
	}

	public byte getVersion() {
		return this.version;
	}

	public byte getType() {
		return this.type;
	}
	
	public byte[] getMessage() {
		return this.message;
	}

	public int length() {
		return this.length;
	}
	
	public byte[] getBytes() {
        byte[] buffer = new byte[this.message.length + 6];
        
        buffer[0] = MSG_HEADER[0];
        buffer[1] = MSG_HEADER[1];
        buffer[2] = MSG_VER_1;
        buffer[3] = this.type;
        buffer[4] = (byte)((this.length >> 8) & 0xFF);
        buffer[5] = (byte)((this.length) & 0xFF);
        System.arraycopy(this.message, 0, buffer, 6, this.length);
		return buffer;
	}

	public String toString() {
        return "Message [dstIP = " + this.dstIPAddress + 
        	   ", dstPort = " + this.dstPort + 
        	   ", version = " + this.version + 
        	   ", type = " + this.type +
        	   ", length = " + this.length + "]";
	}

	private InetAddress dstIPAddress;
	private int dstPort;

	private byte version;
	private byte type;
	private byte[] message;
	private int length;

	private byte[] sessionTicket;
	private byte[] encryptKey;
	
	/* maximum message size */
	private static final int MSG_HEADER_OFFSET = 6;
	private static final int MAX_MSG_SIZE = 4096;
	private static final int MAX_FIELD_SIZE = MAX_MSG_SIZE - MSG_HEADER_OFFSET;

	/* message types */
	public static final byte MSG_SEVER_LOGIN_ATTEMPT_REQUEST = 0x01;
	public static final byte MSG_SEVER_LOGIN_ATTEMPT_RESPNOSE = 0x02;
	
	public static final byte MSG_SEVER_LOGIN_REQUEST = 0x03;
	public static final byte MSG_SEVER_LOGIN_RESPNOSE = 0x04;
	
	public static final byte MSG_SEVER_LOGIN_AUTH_REQUEST = 0x05;
	public static final byte MSG_SEVER_LOGIN_AUTH_RESPNOSE = 0x06;
	
	public static final byte MSG_SEVER_REQUEST = 0x10;
	public static final byte MSG_SEVER_RESPONSE = 0x11;
	public static final byte MSG_CLIENT_REQUEST = 0x20;
	public static final byte MSG_CLIENT_RESPONSE = 0x21;

	/* message version */
	public static final byte MSG_VER_1 = 0x1;
	
	/* Message header */
	public static final byte[] MSG_HEADER = {'I', 'M'};
}
