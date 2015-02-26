/**
 * ClientMessageProcessor.java
 * 
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */
//package IMClient;

//import IMUtil.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.security.*;

public class ClientMessageProcessor {
    public ClientMessageProcessor() {
    	this.aes = new AESCipher();
    	this.rsa = new RSACipher();
    	
        this.clientInfo = new ClientInfo();
        this.sendQueue = new LinkedBlockingQueue<EncryptedMessage>();
        this.receiveQueue = new LinkedBlockingQueue<EncryptedMessage>();
        this.serverSocket = null;
        this.clientSocket = null;
        this.serverInputStream = null;
        this.serverOutputStream = null;
    }
    
    public Socket getServerSocket() {
        return this.serverSocket;
    }

    public InputStream getServerInputStream() {
    	return this.serverInputStream;
    }
    
    public OutputStream getServerOutputStream() {
    	return this.serverOutputStream;
    }
    
    public boolean setServerSocket() {
        try {
            this.serverSocket = new Socket();
            
            // connect to the server
            this.serverSocket.connect(new InetSocketAddress(this.getServerIPAddress(), this.getServerPort()), 
            						  SOCKET_TIMEOUT);
            
            // Set timeout for read
            this.serverSocket.setSoTimeout(SOCKET_TIMEOUT);
            
            if (this.serverSocket != null) {
            	this.serverInputStream = this.serverSocket.getInputStream();
            	this.serverOutputStream = this.serverSocket.getOutputStream();
            }
        } catch (IOException e) {
            return false;
        }
       
        return true;
    }
    
    public boolean setClientSocket() {
    	try {
    		this.clientSocket = new DatagramSocket(CLIENT_PORT);
    		this.clientSocket.setSoTimeout(SOCKET_TIMEOUT);
    	} catch (IOException e) {
    		return false;
    	}
    	
    	return true;
    }
    
    public void setClientName(String name) {
    	this.getClient().setName(name);
    }
    
    public void setClientPassword(String password) {
    	this.aes.generateKey(password.getBytes());
    }
    
    public EncryptedMessage parseLoginAttemptMessage() {
    	EncryptedMessage encryptedMessage = null;
    	InetAddress messageIPAddress = null;
    	int messagePort = 0;
    	byte messageType = 0;
    	byte[] message = null;
    	SubField subField = new SubField();
    
    	this.getClient().loginDHNumber = DHCipher.generateRandom128();
    	
    	subField.type = SubField.MSG_TYPE_LOGIN_ATTEMPT;
    	subField.setUsername(getClient().getName());
    	subField.seed = this.aes.encryptBytes(this.getClient().loginDHNumber);
    	
    	SessionTicket sessionTicket = new SessionTicket();
    	
    	//System.out.println(sessionTicket.getBytes().length);
    	//System.out.println(subField.getBytes().length);
    	
    	EncryptedField encryptedField = new EncryptedField(this.aes.encryptBytes(sessionTicket.getBytes()),
    													   subField.getBytes());
    	
    	messageIPAddress = getServerIPAddress();
    	messagePort = getServerPort();
    	messageType = EncryptedMessage.MSG_SEVER_LOGIN_ATTEMPT_REQUEST;
    	message = encryptedField.getBytes();
    	
        encryptedMessage = new EncryptedMessage(messageIPAddress, messagePort, messageType, message);
        System.out.println(encryptedMessage);
        
        return encryptedMessage;
    }
    
    public EncryptedMessage parseLoginMessage() {
    	InetAddress messageIPAddress = null;
    	int messagePort = 0;
    	byte messageType = 0;
    	byte[] message = null;
    	
    	SubField subField = new SubField();
    	SessionTicket sessionTicket = new SessionTicket();
    	
    	EncryptedField encryptedField = new EncryptedField(this.aes.encryptBytes(sessionTicket.getBytes()),
    													   this.aes.encryptBytes(subField.getBytes()));
    	
    	messageIPAddress = getServerIPAddress();
    	messagePort = getServerPort();
    	messageType = EncryptedMessage.MSG_SEVER_LOGIN_REQUEST;
    	message = encryptedField.getBytes();
    	
        return new EncryptedMessage(messageIPAddress, messagePort, messageType, message);
    }
   
    public EncryptedMessage parseLoginAuthenticateMessage() {
    	InetAddress messageIPAddress = null;
    	int messagePort = 0;
    	byte messageType = 0;
    	byte[] message = null;
    	
    	SubField subField = new SubField();
    	SessionTicket sessionTicket = new SessionTicket();
    	EncryptedField encryptedField = new EncryptedField(this.aes.encryptBytes(sessionTicket.getBytes()),
    													   this.aes.encryptBytes(subField.getBytes()));
    	
    	messageIPAddress = getServerIPAddress();
    	messagePort = getServerPort();
    	messageType = EncryptedMessage.MSG_SEVER_LOGIN_AUTH_REQUEST;
    	message = encryptedField.getBytes();
    	
        return new EncryptedMessage(messageIPAddress, messagePort, messageType, message);
    }
    
    public EncryptedField sendTaskList() {
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	
    	byte[] encryptedSubFieldBytes = null;
    	byte[] encryptedSessionTicketBytes = null;
    
    	AESCipher messageCipher = new AESCipher(this.getClient().messageSessionKey, this.getClient().messageSessionKey);
    	
    	SubField subField = new SubField();
    	subField.type = SubField.MSG_TYPE_LIST;
    	subField.setUsername(this.getClient().getName());
    	subField.setTimestamp(new Date().getTime());
    	/*
    	try {
    		subField.hashSessionTicket = Hasher.bytesToSHA256(getClient().serverSessionTicket);
    	} catch (NoSuchAlgorithmException e) {}
    	*/
    	encryptedSubFieldBytes = messageCipher.encryptBytes(subField.getBytes());
    			
    	//return new EncryptedField(encryptedSubFieldBytes, this.getClient().serverSessionTicket);
    	return new EncryptedField(encryptedSubFieldBytes, null);
    }
    
    public EncryptedField renewTicket() {
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	
    	byte[] encryptedSubFieldBytes = null;
    	byte[] encryptedSessionTicketBytes = null;
    	
    	AESCipher messageCipher = new AESCipher(this.getClient().messageSessionKey, this.getClient().messageSessionKey);
    	
    	SubField subField = new SubField();
    	subField.type = SubField.MSG_TYPE_MST;
    	subField.setUsername(this.getClient().getName());
    	subField.setTimestamp(new Date().getTime());
    	try {
    		subField.hashSessionTicket = Hasher.bytesToSHA256(getClient().serverSessionTicket);
    	} catch (NoSuchAlgorithmException e) {}
    	encryptedSubFieldBytes = messageCipher.encryptBytes(subField.getBytes());
    			
    	return new EncryptedField(encryptedSubFieldBytes, this.getClient().serverSessionTicket);
    }
    
    public EncryptedField sendMessage(String dstClient, String message) {
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	
    	byte[] encryptedSubFieldBytes = null;
    	byte[] encryptedSessionTicketBytes = null;
    	
    	this.currentDstClient = dstClient;
    	this.currentDstClientMessage = message;
    	
    	//AESCipher messageCipher = new AESCipher(this.getClient().messageSessionKey, this.getClient().messageSessionKey);
    	AESCipher messageCipher = this.getAESCipher();
    	
    	SubField subField = new SubField();
    	subField.type = SubField.MSG_TYPE_PKEY;
    	subField.setUsername(this.getClient().getName());
    	subField.setTimestamp(new Date().getTime());
    	//subField.clientUsername = dstClient.getBytes();
    	/*
    	try {
    		subField.hashSessionTicket = Hasher.bytesToSHA256(getClient().serverSessionTicket);
    	} catch (NoSuchAlgorithmException e) {}
    	*/
    	encryptedSubFieldBytes = messageCipher.encryptBytes(subField.getBytes());
    			
    	//return new EncryptedField(encryptedSubFieldBytes, this.getClient().serverSessionTicket);
    	return new EncryptedField(encryptedSubFieldBytes, null);
    }
    
    // client types "send use1 message1" 
    // 
    public EncryptedField sendLogout() {
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	
    	byte[] encryptedSubFieldBytes = null;
    	byte[] encryptedSessionTicketBytes = null;
    
    	AESCipher messageCipher = new AESCipher(this.getClient().messageSessionKey, this.getClient().messageSessionKey);
    	
    	SubField subField = new SubField();
    	subField.type = SubField.MSG_TYPE_LOGOUT;
    	subField.setUsername(this.getClient().getName());
    	subField.setTimestamp(new Date().getTime());
    	/*
    	try {
    		subField.hashSessionTicket = Hasher.bytesToSHA256(getClient().serverSessionTicket);
    	} catch (NoSuchAlgorithmException e) {}
    	encryptedSubFieldBytes = messageCipher.encryptBytes(subField.getBytes());
    	*/		
    	//return new EncryptedField(encryptedSubFieldBytes, this.getClient().serverSessionTicket);
    	return new EncryptedField(encryptedSubFieldBytes, null);
    }
    
    // Commands
    public synchronized void offerCommand(byte taskIndex, Matcher matcher) {
    	byte type = taskIndex;
    	InetAddress messageIPAddress = getServerIPAddress();
    	int messagePort = getServerPort();
    	byte messageType = EncryptedMessage.MSG_SEVER_REQUEST;
    	byte[] message = null;
    	EncryptedField field = null;
    
    	switch (type) {
        	case TASK_LIST: 
        		field = sendTaskList();
        		break;
        		
        	case TASK_SEND:
        		if (currentDstClient == null) {
        			field = sendMessage(matcher.group(1), matcher.group(2));
        		} else {
        			System.out.println("wait the last message send");
        		}
        		break;
        	
        	case TASK_LOGOUT:
        		field = sendLogout();
        		break;
    	}
    	if (field != null) {
    		message = field.getBytes();
    		send(new EncryptedMessage(messageIPAddress, messagePort, messageType, message));
    	}
    }
   
    // parse the message and put it into send Queue
    public void send(EncryptedMessage message) {
    	System.out.println("send");
        // put the message into the send queue
        sendQueue.offer(message);
    }
    
    // put the message into the message queue
    public void recv(EncryptedMessage message) {
    	System.out.println("recv");
        // recv the message from the recieve queue
        receiveQueue.offer(message);
    }

    public ClientInfo getClient() {
        return this.clientInfo;
    }

    public LinkedBlockingQueue<EncryptedMessage> getSendList() {
    	return this.sendQueue;
    }
    
    public LinkedBlockingQueue<EncryptedMessage> getReceiveList() {
    	return this.receiveQueue;
    }
  
    public InetAddress getServerIPAddress() {
    	return this.serverIPAddress;
    }

    public DatagramSocket getClientSocket() {
    	return this.clientSocket;
    }
    
    public int getServerPort() {
    	return this.serverPort;
    }
    
    public void setServerIPAddress(InetAddress address) {
    	this.serverIPAddress = address;
    }
    
    public void setServerPort(int port) {
    	this.serverPort = port;
    }

    public AESCipher getAESCipher() {
    	return this.aes;
    }
    
    public RSACipher getRSACipher() {
    	return this.rsa;
    }
    
    public volatile boolean isLoginAttemptSucceed;
    public volatile boolean isLoginSucceed;
    public volatile boolean isLoginAuthenticateSucceed;
    
    // ciphers
    private AESCipher aes;
    private RSACipher rsa;
    
    // user list
    private ConcurrentHashMap<String, ClientSessionInfo> clientList;

    // critical area
    private LinkedBlockingQueue<EncryptedMessage> sendQueue;
    private LinkedBlockingQueue<EncryptedMessage> receiveQueue;

    // Client Info
    private ClientInfo clientInfo;
    
    public String currentDstClient;
    public InetAddress currentDstClientIP;
    public int currentDstClientPort;
    public String currentDstClientMessage;
    
    // Server Info
    private InetAddress serverIPAddress;
    private int serverPort;
    public byte[] serverID;
    
    // Session Client Info
    public LinkedBlockingQueue<ClientSessionInfo> sessionInfo;

    // TCP Socket for server communication
    private Socket serverSocket;
    private InputStream serverInputStream;
    private OutputStream serverOutputStream;
    
    // UDP Socket for client communication
    private DatagramSocket clientSocket;

    public static final byte TASK_INIT   = 0x0;
    public static final byte TASK_LIST   = 0x1;
    public static final byte TASK_SEND   = 0x2;
    public static final byte TASK_LOGOUT = 0x3;
    
    private final static int CLIENT_PORT = 8081;
    private final static int SOCKET_TIMEOUT = 1000;
}