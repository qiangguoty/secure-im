/* 
 * SubField.java
 *
 * @Date: 2014, March 22
 * 
 * @Note: This is the main class to encrypt the message
 * 
 * �LOGIN� | UserID | timestamp | Hash(LAST) | Answer1 | {Challenge2}KC
 * 
 */

import java.util.List;
import java.util.LinkedList;
import java.util.Arrays;

public class SubField {
	
	public SubField() {
		this.type = 0;
		this.username = new byte[MSG_SIZE_32];
		this.userNum = 0;
		this.userList = new byte[MSG_SIZE_512];
		this.seed = new byte[MSG_SIZE_32];
		this.challenge = new byte[MSG_SIZE_32];
		this.answer = new byte[MSG_SIZE_32];
		this.hashSessionTicket = new byte[MSG_SIZE_32];
		this.sessionKey = new byte[MSG_SIZE_32];
		this.sessionTicket = new byte[MSG_SIZE_256];
		this.clientPublicKey = new byte[MSG_SIZE_32];
		this.clientUsername = new byte[MSG_SIZE_32];
		this.clientMessageSessionKey = new byte[MSG_SIZE_32];
		this.clientMessageSessionTicket = new byte[MSG_SIZE_256];
		this.message = new byte[MSG_SIZE_256];
		this.hashMessage = new byte[MSG_SIZE_32];
		this.timestamp = new byte[MSG_SIZE_8];
	}

    public SubField(byte[] bytes) {
        if (bytes.length == SIZE) {
            this.bytes = bytes;
            this.type = bytes[0];
            this.username = Arrays.copyOfRange(bytes, 1, 33);
            this.userNum = bytes[33];
            this.userList = Arrays.copyOfRange(bytes, 34, 546);   // 512
            this.seed =  Arrays.copyOfRange(bytes, 546, 578);     // 32
            this.challenge = Arrays.copyOfRange(bytes, 578, 610); // 32
            this.answer = Arrays.copyOfRange(bytes, 610, 642);    // 32
            this.hashSessionTicket = Arrays.copyOfRange(bytes, 642, 674); //32
            this.sessionKey = Arrays.copyOfRange(bytes, 674, 706);  //32
            this.sessionTicket = Arrays.copyOfRange(bytes, 706, 962); //256
            this.clientPublicKey = Arrays.copyOfRange(bytes, 962, 994); // 32
            this.clientUsername = Arrays.copyOfRange(bytes, 994, 1026); // 32
            this.clientMessageSessionKey = Arrays.copyOfRange(bytes, 1026, 1058); // 32
            this.clientMessageSessionTicket = Arrays.copyOfRange(bytes, 1058, 1314); // 256
            this.message = Arrays.copyOfRange(bytes, 1314, 1570); // 256
            this.hashMessage = Arrays.copyOfRange(bytes, 1570, 1602); // 32
            this.timestamp = Arrays.copyOfRange(bytes, 1602, 1610); // 8
        }
    }

	public byte[] getBytes() {
		byte[] bytes = new byte[SIZE];

		bytes[0] = this.type;
		System.arraycopy(this.username, 0, bytes, 1, MSG_SIZE_32);
		bytes[33] = this.userNum;
		System.arraycopy(this.userList, 0, bytes, 34, MSG_SIZE_512);
		System.arraycopy(this.seed, 0, bytes, 546, MSG_SIZE_32);
		System.arraycopy(this.challenge, 0, bytes, 578, MSG_SIZE_32);
		System.arraycopy(this.answer, 0, bytes, 610, MSG_SIZE_32);
		System.arraycopy(this.hashSessionTicket, 0, bytes, 642, MSG_SIZE_32);
		System.arraycopy(this.sessionKey, 0, bytes, 674, MSG_SIZE_32);
		System.arraycopy(this.sessionTicket, 0, bytes, 706, MSG_SIZE_256);
		System.arraycopy(this.clientPublicKey, 0, bytes, 962, MSG_SIZE_32);
		System.arraycopy(this.clientUsername, 0, bytes, 994, MSG_SIZE_32);
		System.arraycopy(this.clientMessageSessionKey, 0, bytes, 1026, MSG_SIZE_32);
		System.arraycopy(this.clientMessageSessionTicket, 0, bytes, 1058, MSG_SIZE_256);
		System.arraycopy(this.message, 0, bytes, 1314, MSG_SIZE_256);
		System.arraycopy(this.hashMessage, 0, bytes, 1570, MSG_SIZE_32);
		System.arraycopy(this.timestamp, 0, bytes, 1602, MSG_SIZE_8);
	
		this.bytes = bytes;
		return bytes;
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
	
	public void setTimestamp(long timestamp) {
		this.timestamp = new byte[MSG_SIZE_8];
		this.timestamp[0] = (byte) ((timestamp >> 56) & 0xFF);
		this.timestamp[1] = (byte) ((timestamp >> 48) & 0xFF);
		this.timestamp[2] = (byte) ((timestamp >> 40) & 0xFF);
		this.timestamp[3] = (byte) ((timestamp >> 32) & 0xFF);
		this.timestamp[4] = (byte) ((timestamp >> 24) & 0xFF);
		this.timestamp[5] = (byte) ((timestamp >> 16) & 0xFF);
		this.timestamp[6] = (byte) ((timestamp >> 8) & 0xFF);
		this.timestamp[7] = (byte) ((timestamp >> 0) & 0xFF);
	}
	
	public void setUsername(String name) {
		this.username = new byte[MSG_SIZE_32];
        if (name != null) {
            System.arraycopy(name.getBytes(), 0, this.username, 0, Math.min(MSG_SIZE_32, name.getBytes().length));
        }
	}
	
	public String getUsername() {
		return new String(this.username);
	}

    public int getUserNum() {
        return (int)userNum;
    }

    public List<String> getUserList() {
        List<String> result = new LinkedList<String>();

        for (int i = 0; i < this.getUserNum(); i++) {
            byte[] slice = Arrays.copyOfRange(this.userList, i * 32, (i + 1) * 32);
            result.add(new String(slice));
        }
        return result;
    }

    public String getMessage() {
        return new String(this.message);
    }

    public void setMessage(String msg) {
        byte[] msgBytes = msg.getBytes();
        if (msgBytes != null) {
            this.message = new byte[MSG_SIZE_256];
            System.arraycopy(msgBytes, 0, this.username, 0, Math.min(MSG_SIZE_256, msgBytes.length));
        }
        else {
            this.message = null;
        }
    }
	
	public byte[] bytes;
	public byte type;
	public byte[] username;
	public byte userNum;         //
	public byte[] userList;      // 32 x 10
	public byte[] seed;
	public byte[] challenge;
	public byte[] answer;
	public byte[] hashSessionTicket;
	public byte[] sessionKey;
	public byte[] sessionTicket;
	public byte[] clientPublicKey;
	public byte[] clientUsername;
	public byte[] clientMessageSessionKey;
	public byte[] clientMessageSessionTicket;
	public byte[] message;
	public byte[] hashMessage;
	public byte[] timestamp;

	public static final int MSG_SIZE_1 = 1;
	public static final int MSG_SIZE_8 = 8;
	public static final int MSG_SIZE_16 = 16;
	public static final int MSG_SIZE_32 = 32;
	public static final int MSG_SIZE_256 = 256;
	public static final int MSG_SIZE_512 = 512;
	
	public static final int SIZE = 1610;   // used to be 1498
	public static final int ENCRYPT_SIZE= 1610;
	
	/* transaction type */
	public static final byte MSG_TYPE_LOGIN_ATTEMPT = 0x1;
	public static final byte MSG_TYPE_LOGIN = 0x2;
	public static final byte MSG_TYPE_LOGIN_ACK = 0x3;
	public static final byte MSG_TYPE_LOGIN_AUTH = 0x4;
	public static final byte MSG_TYPE_LOGIN_AUTH_ACK = 0x5;
	public static final byte MSG_TYPE_LIST = 0x6;
	public static final byte MSG_TYPE_LIST_ACK = 0x7;
	public static final byte MSG_TYPE_PKEY = 0x8;
	public static final byte MSG_TYPE_PKEY_ACK = 0x9;
	public static final byte MSG_TYPE_DH = 0xA;
	public static final byte MSG_TYPE_DH_ACK = 0xB;
	public static final byte MSG_TYPE_MSG = 0xC;
	public static final byte MSG_TYPE_MSG_ACK = 0xD;
	public static final byte MSG_TYPE_MST = 0xE;
	public static final byte MSG_TYPE_MST_ACK = 0xF;
	public static final byte MSG_TYPE_LOGOUT = 0x10;
	public static final byte MSG_TYPE_LOGOUT_ACK = 0x11;
}
