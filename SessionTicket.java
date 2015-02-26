/* 
 * SessionTicket.java
 *
 * @Date: 2014, March 22
 * 
 * @Note: This is the main class to encrypt the message
 * 
 * IM | Version | Type | Field
 * 01      2       3          4+
 *
 */
//package IMUtil;

import java.util.Arrays;

public class SessionTicket {
	public static void main(String[] args) {
		SessionTicket ticket = new SessionTicket(null, null, null, -1, -1);
		SessionTicket ticket2 = new SessionTicket(null);
		
		ticket = new SessionTicket(null, null, null, 1000, 2000);
		
		System.out.println(ticket.getTimestamp());
		System.out.println(ticket.getValidTime());
		
		System.out.println(ticket.equals(ticket2));
	}
	
	public SessionTicket() {
		this.bytes = new byte[this.SIZE];
		this.sessionKey = new byte[SESSION_KEY_SIZE];
		this.sessionIV = new byte[SESSION_IV_SIZE];
		this.timestamp = new byte[TIMESTAMP_SIZE];
		this.validTime = new byte[VALIDDATE_SIZE];
	}
	
	public SessionTicket(byte[] username, byte[] sessionKey, byte[] sessionIV, long timestamp, long validTime) {
		if (username != null) {
			this.username = new byte[USER_NAME_SIZE];
			System.arraycopy(username, 0, this.username, 0, Math.min(USER_NAME_SIZE, username.length));
		}
		else {
			this.username = null;
		}
		
		if (sessionKey != null) {
			this.sessionKey = new byte[SESSION_KEY_SIZE];
			System.arraycopy(sessionKey, 0, this.sessionKey, 0, Math.min(SESSION_KEY_SIZE, sessionKey.length));
		}
		else {
			this.sessionKey = null;
		}
		
		if (sessionIV != null) {
			this.sessionIV = new byte[SESSION_IV_SIZE];
			System.arraycopy(sessionIV, 0, this.sessionIV, 0, Math.min(SESSION_IV_SIZE, sessionIV.length));
		}
		else {
			this.sessionIV = null;
		}
		
		if (timestamp >= 0) {
			this.timestamp = new byte[TIMESTAMP_SIZE];
			this.timestamp[0] = (byte) ((timestamp >> 56) & 0xFF);
			this.timestamp[1] = (byte) ((timestamp >> 48) & 0xFF);
			this.timestamp[2] = (byte) ((timestamp >> 40) & 0xFF);
			this.timestamp[3] = (byte) ((timestamp >> 32) & 0xFF);
			this.timestamp[4] = (byte) ((timestamp >> 24) & 0xFF);
			this.timestamp[5] = (byte) ((timestamp >> 16) & 0xFF);
			this.timestamp[6] = (byte) ((timestamp >> 8) & 0xFF);
			this.timestamp[7] = (byte) ((timestamp >> 0) & 0xFF);
		}
		else {
			this.timestamp = null;
		}
				
		if (validTime >= 0) {
			this.validTime = new byte[VALIDDATE_SIZE];
			this.validTime[0] = (byte) ((validTime >> 56) & 0xFF);
			this.validTime[1] = (byte) ((validTime >> 48) & 0xFF);
			this.validTime[2] = (byte) ((validTime >> 40) & 0xFF);
			this.validTime[3] = (byte) ((validTime >> 32) & 0xFF);
			this.validTime[4] = (byte) ((validTime >> 24) & 0xFF);
			this.validTime[5] = (byte) ((validTime >> 16) & 0xFF);
			this.validTime[6] = (byte) ((validTime >> 8) & 0xFF);
			this.validTime[7] = (byte) ((validTime >> 0) & 0xFF);
		}
		else {
			this.validTime = null;
		}
		
		this.bytes = new byte[USER_NAME_SIZE + SESSION_KEY_SIZE + TIMESTAMP_SIZE + VALIDDATE_SIZE];
		if (username != null) {
			System.arraycopy(this.username, 0, this.bytes, 0, USER_NAME_SIZE);
		}
		if (sessionKey != null) {
			System.arraycopy(this.sessionKey, 0, this.bytes, USER_NAME_SIZE, SESSION_KEY_SIZE);
		}
		
		System.arraycopy(this.timestamp, 0, this.bytes, USER_NAME_SIZE + SESSION_KEY_SIZE, TIMESTAMP_SIZE);
		System.arraycopy(this.validTime, 0, this.bytes, USER_NAME_SIZE + SESSION_KEY_SIZE + TIMESTAMP_SIZE, VALIDDATE_SIZE);
	}

	public SessionTicket(byte[] rawText) {
		if (rawText != null) {
			this.bytes = rawText;
			this.username = new byte[USER_NAME_SIZE];
			this.sessionKey = new byte[SESSION_KEY_SIZE];
			this.sessionIV = new byte[SESSION_IV_SIZE];
			this.timestamp = new byte[TIMESTAMP_SIZE];
			this.validTime = new byte[VALIDDATE_SIZE];
		
			// get the field
			System.arraycopy(this.bytes, 0, this.username, 0, USER_NAME_SIZE);
			System.arraycopy(this.bytes, USER_NAME_SIZE, this.sessionKey, 0, SESSION_KEY_SIZE);
			System.arraycopy(this.bytes, USER_NAME_SIZE + SESSION_KEY_SIZE, this.sessionIV, 0, SESSION_IV_SIZE);
			System.arraycopy(this.bytes, USER_NAME_SIZE + SESSION_KEY_SIZE + SESSION_IV_SIZE, this.timestamp, 0, TIMESTAMP_SIZE);
			System.arraycopy(this.bytes, USER_NAME_SIZE + SESSION_KEY_SIZE + SESSION_IV_SIZE + TIMESTAMP_SIZE, this.validTime, 0, VALIDDATE_SIZE);
		}
		else {
			this.bytes = null;
			this.username = null;
			this.sessionKey = null;
			this.timestamp = null;
			this.validTime = null;
		}
	}

	public byte[] getBytes() {
		return this.bytes;
	}
	
	public byte[] getUserName() {
		return this.username;
	}

	public void setSessionKey(byte[] sessionKey) {
		if (sessionKey != null) {
			this.sessionKey = new byte[SESSION_KEY_SIZE];
			System.arraycopy(sessionKey, 0, this.sessionKey, 0, Math.min(SESSION_KEY_SIZE, sessionKey.length));
		}
		else {
			this.sessionKey = null;
		}
	}
	
	public byte[] getSessionKey() {
		return this.sessionKey;
	}

	public void setSessionIV(byte[] sessionIV) {
		if (sessionIV != null) {
			this.sessionIV = new byte[SESSION_IV_SIZE];
			System.arraycopy(sessionIV, 0, this.sessionIV, 0, Math.min(SESSION_IV_SIZE, sessionIV.length));
		}
		else {
			this.sessionIV = null;
		}
	}
	
	public byte[] getSessionIV() {
		return this.sessionIV;
	}
	
	public byte[] getTimestampBytes() {
		return this.timestamp;
	}
	
	public byte[] getValidTimeBytes() {
		return this.validTime;
	}

	public long getTimestamp() {
		return ((this.timestamp[7] & 0xFF) |
				(this.timestamp[6] & 0xFF) << 8 |
				(this.timestamp[5] & 0xFF) << 16 |
				(this.timestamp[4] & 0xFF) << 24 |
				(this.timestamp[3] & 0xFF) << 32 |
				(this.timestamp[2] & 0xFF) << 40 |
				(this.timestamp[1] & 0xFF) << 48 |
				(this.timestamp[0] & 0xFF) << 56);
	}

	public long getValidTime() {
		return ((this.validTime[7] & 0xFF) |
				(this.validTime[6] & 0xFF) << 8 |
				(this.validTime[5] & 0xFF) << 16 |
				(this.validTime[4] & 0xFF) << 24 |
				(this.validTime[3] & 0xFF) << 32 |
				(this.validTime[2] & 0xFF) << 40 |
				(this.validTime[1] & 0xFF) << 48 |
				(this.validTime[0] & 0xFF) << 56);
	}

	@Override
	public boolean equals(Object o) {
		if (o == null) {
			return true;
		}
		
		if (o instanceof SessionTicket) {
			if (Arrays.equals(this.username, ((SessionTicket) o).getUserName()) == false) {
				return false;
			}
			if (Arrays.equals(this.sessionKey, ((SessionTicket) o).getSessionKey()) == false) {
				return false;
			}
			if (Arrays.equals(this.timestamp, ((SessionTicket)o ).getTimestampBytes()) == false) {
				return false;
			}
			if (Arrays.equals(this.validTime, ((SessionTicket) o).getValidTimeBytes()) == false) {
				return false;
			}
		}
		
		return true;
	}
	// fields in session key
	private byte[] username;
	private byte[] sessionKey;
	private byte[] sessionIV;
	
	private byte[] timestamp;
	private byte[] validTime;

	// plain session key bytes
	private byte[] bytes;

	public static int ENCRYPTED_SIZE = 208;
	public static int SIZE = 192;
	
	private static int USER_NAME_SIZE = 32;
	private static int SESSION_KEY_SIZE = 128;
	private static int SESSION_IV_SIZE = 16;
	private static int TIMESTAMP_SIZE = 8;
	private static int VALIDDATE_SIZE = 8;
	private static int OTHER_SIZE = 16; // TBD
}
