/**
 * ServerProcessWorker.java
 * 
 * A Process Worker can work on both side, given the property
 * 
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */

//package IMServer;

//import IMUtil.*;

import java.util.*;
import java.io.*;
import java.net.*;
import java.security.*;

public class ServerProcessWorker implements Runnable {
    public ServerProcessWorker(ServerMessageProcessor processor, Socket socket) {
        this.messageProcessor = processor;
        this.isRunning = true;
        this.type = WORKER_INIT;
        this.socket = socket;
        
        try {
        	this.socketInputStream = this.socket.getInputStream();
        	this.socketOutputStream = this.socket.getOutputStream();
        } catch (IOException e) {
        	
        }
    }

    @Override
    public void run() {
        byte[] recvBuffer = null;
        byte[] sendBuffer = null;
        int recvLength;
        int sendLength;
        EncryptedMessage message = null;
        EncryptedMessage responseMessage = null;
       
        try {
        	socketInputStream = this.socket.getInputStream();
        	socketOutputStream = this.socket.getOutputStream();
        } catch (IOException e) {
        	System.out.println("failed to create stream");
        }
        System.out.println("ServerProcessWorker for " + this.socket.getRemoteSocketAddress());
 
        while (this.isRunning) {
        	try {
        		if (socketInputStream.available() > 0) {
        			System.out.println("handle");
        			recvBuffer = new byte[MAX_BUFFER_SIZE];
        			recvLength = socketInputStream.read(recvBuffer);
        			if (recvLength > 0) {
        				message = new EncryptedMessage(this.socket.getInetAddress(), 
        											   this.socket.getPort(), 
        											   recvBuffer);
        			
        				System.out.println("Recv " + message);
        				responseMessage = processMessage(message);
        			
        				if (responseMessage != null) {
        					System.out.println("Send " + responseMessage);
        					System.out.println("Send ack");
        					socketOutputStream.write(responseMessage.getBytes());
        				}
        			}
        		}
        	} catch (IOException e) {
        		System.out.println("Receive failed");
        	}
        }
    }
   
    public EncryptedMessage processRequest(EncryptedField field) {
    	byte[] encryptedSessionTicketBytes = field.getEncryptedSessionTicketByte();
    	byte[] sessionTicketBytes = this.messageProcessor.getAESCipher().decryptBytes(encryptedSessionTicketBytes);
    	
    	SessionTicket sessionTicket = new SessionTicket(sessionTicketBytes);
    	
    	// Check the valid time
    	if (Math.abs(new Date().getTime() - sessionTicket.getValidTime()) > MSG_VALID_PERIOD) {
    		return null;
    	}
    	AESCipher clientAESCipher = new AESCipher(sessionTicket.getSessionIV(), sessionTicket.getSessionKey());
    	
    	byte[] encryptedSubFieldBytes = field.getEncryptedSubFieldBytes();
    	byte[] subFieldBytes = clientAESCipher.decryptBytes(encryptedSubFieldBytes);
    	SubField subField = new SubField(subFieldBytes);
    	// handle the object
    	switch (subField.type) {
    		case SubField.MSG_TYPE_LOGIN:
                return processLoginRequest(field);
    		case SubField.MSG_TYPE_LOGIN_AUTH:
                return processLoginAuthRequest(field);
    		case SubField.MSG_TYPE_LIST:
                return processListRequest(field);
    		case SubField.MSG_TYPE_MST:
                return processMSTRequest(field);
    		case SubField.MSG_TYPE_PKEY:
                return processPKEYRequest(field);
    		case SubField.MSG_TYPE_LOGOUT:
                return processLogoutRequest(field);
    	}
    	
    	return null;
    }
    
    public EncryptedMessage processLoginAttemptRequest(EncryptedField field) {
    	System.out.println("Handle Login Attempt Request " + field.getEncryptedSubFieldBytes().length);
    	
    	SubField subField = new SubField(field.getEncryptedSubFieldBytes());
    	SubField sendSubField = null;
    	SessionTicket sendSessionTicket = null;
    	
    	long timestamp;
    	String clientUsername;
    	byte[] clientMasterKey;
    	byte[] clientDHPublicKey;
    	byte[] serverDHNumber;
    	byte[] serverDHPublicKey;
    	byte[] DHEncryptKey;
    	byte[] encryptedFieldBytes;
    	
    	EncryptedMessage responseMessage = null;
    	
    	if ((subField != null) && (subField.type == SubField.MSG_TYPE_LOGIN_ATTEMPT)) {
    		System.out.println("Handle LOGIN_ATTEMPT");
    	
    		// username
    		clientUsername = new String(subField.username);
    		
    		// retrieve the key
    		clientMasterKey = this.messageProcessor.getUserMasterKey(clientUsername);
    		AESCipher clientAESCipher = new AESCipher(clientMasterKey, clientMasterKey);
    	
    		// parse client DH public key 128bit
    		clientDHPublicKey = subField.seed;
    
    		// parse server DH public number and 
    		serverDHNumber = DHCipher.generateRandom128();
    		serverDHPublicKey = DHCipher.generateDHPublicKey(serverDHNumber);
    	
    		DHEncryptKey = DHCipher.generateEncryptKey(clientDHPublicKey, serverDHNumber);
    		
    		//////////////////  RESPONSE ////////////////////
    		
    		timestamp = new Date().getTime();
    		sendSessionTicket = new SessionTicket(subField.username, null, null, timestamp, timestamp + LOGIN_VALID_PERIOD);
    		sendSessionTicket.setSessionKey(DHEncryptKey);
    		sendSessionTicket.setSessionIV(DHEncryptKey);
   
    		// generate DH Encrypt Key
    		AESCipher aesCipher = new AESCipher(DHEncryptKey, DHEncryptKey);
    		try {
    			AESCipher.generateSessionKey(sendSessionTicket);
    		} catch (NoSuchAlgorithmException e) {}
    	
    		sendSubField = new SubField();
            sendSubField.seed = this.messageProcessor.getAESCipher().encryptBytes(serverDHPublicKey);
            sendSubField.challenge = aesCipher.encryptBytes(DHCipher.generateRandom128());
            
            System.out.println(sendSubField.seed.length);
            System.out.println(sendSubField.challenge.length);
            
            /////////////////  FINISH   ////////////////////
            EncryptedField sendField = new EncryptedField(sendSessionTicket.getBytes(), sendSubField.getBytes());
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
            									   EncryptedMessage.MSG_SEVER_LOGIN_RESPNOSE, encryptedFieldBytes);
            System.out.println("Login Attempt done");
            
            this.messageProcessor.loginUser(clientUsername, socket.getInetAddress(), socket.getPort());
    	}
    	
    	return responseMessage;
    }

    public EncryptedMessage processLoginRequest(EncryptedField field) {
        SubField subField = new SubField(field.getEncryptedSubFieldBytes());
        SubField sendSubField = null;
        EncryptedMessage responseMessage = null;
        SessionTicket sendSessionTicket = null;
        byte[] encryptedFieldBytes;
    	String clientUsername;
    	byte[] clientMasterKey;
    	long timestamp;
    	
    	clientUsername = new String(subField.username);
    	clientMasterKey = this.messageProcessor.getUserMasterKey(clientUsername);
    	
        if ((subField != null) && (subField.type == SubField.MSG_TYPE_LOGIN)) {
            sendSubField = new SubField();
            // ServerID
            sendSubField.username = this.messageProcessor.getServer().getServerName();
            // Timestamp
            sendSubField.setTimestamp(ValidationHelper.getCurrentTimestamp());

            // Kls
            byte[] Kls = DHCipher.generateRandom128();
            sendSubField.sessionKey = Kls;

            // LST
    		timestamp = new Date().getTime();
            sendSessionTicket = new SessionTicket(subField.username, null, null, timestamp, timestamp + LOGIN_VALID_PERIOD);
            sendSessionTicket.setSessionKey(Kls);
            sendSessionTicket.setSessionIV(Kls);

            AESCipher aesCipher = new AESCipher(Kls, Kls);
            try {
                AESCipher.generateSessionKey(sendSessionTicket);
            } catch (NoSuchAlgorithmException e) {}

            EncryptedField sendField = new EncryptedField(
                    sendSessionTicket.getBytes(),
                    sendSubField.getBytes());

    		AESCipher clientAESCipher = new AESCipher(clientMasterKey, clientMasterKey);
    		
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
                    EncryptedMessage.MSG_SEVER_RESPONSE, encryptedFieldBytes);
        }

        return responseMessage;
    }

    public EncryptedMessage processLoginAuthRequest (EncryptedField field) {
        SubField subField = new SubField(field.getEncryptedSubFieldBytes());
    	SubField sendSubField = null;
        SessionTicket sendSessionTicket = null;
        EncryptedMessage responseMessage = null;
        byte[] encryptedFieldBytes;
    	long timestamp;
    	String clientUsername;
    	byte[] clientMasterKey;
    	
        byte[] Kms = null;
        if ((subField != null)) {
            sendSubField = new SubField();
            // ServerID
            sendSubField.username = this.messageProcessor.getServer().getServerName();
            // Timestamp
            sendSubField.setTimestamp(ValidationHelper.getCurrentTimestamp());

            // Kms
            Kms = DHCipher.generateRandom128();
            sendSubField.sessionKey = Kms;

            // MST
    		timestamp = new Date().getTime();
            sendSessionTicket = new SessionTicket(subField.username, null, null, timestamp, timestamp + LOGIN_VALID_PERIOD);
            sendSessionTicket.setSessionKey(Kms);
            sendSessionTicket.setSessionIV(Kms);

            AESCipher aesCipher = new AESCipher(Kms, Kms);
            try {
                AESCipher.generateSessionKey(sendSessionTicket);
            } catch (NoSuchAlgorithmException e) {}

            EncryptedField sendField = new EncryptedField(
                    sendSessionTicket.getBytes(),
                    sendSubField.getBytes());
            
            AESCipher clientAESCipher = this.messageProcessor.getAESCipher();
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
                    EncryptedMessage.MSG_SEVER_RESPONSE, encryptedFieldBytes);
        }

        // added the user into list
        
        return responseMessage;
    }

    public EncryptedMessage processListRequest (EncryptedField field) {
    	SubField sendSubField = null;
        SubField subField = new SubField(field.getEncryptedSubFieldBytes());
        EncryptedMessage responseMessage = null;
        byte[] encryptedFieldBytes;
    	long timestamp;
    	String clientUsername;
    	byte[] clientMasterKey;

        if ((subField != null)) {
            sendSubField = new SubField();
            // ServerID
            sendSubField.username = this.messageProcessor.getServer().getServerName();
            // Timestamp
            sendSubField.setTimestamp(ValidationHelper.getCurrentTimestamp());
            // UserInfoList
            byte[] clientList = this.messageProcessor.getClientList();
            sendSubField.userList = clientList;

            EncryptedField sendField = new EncryptedField( null, sendSubField.getBytes());
            AESCipher clientAESCipher = this.messageProcessor.getAESCipher();
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
                    EncryptedMessage.MSG_SEVER_RESPONSE, encryptedFieldBytes);
        }

        return responseMessage;
    }

    public EncryptedMessage processMSTRequest (EncryptedField field) {
        SubField subField = new SubField(field.getEncryptedSubFieldBytes());
    	SubField sendSubField = null;
    	SessionTicket sendSessionTicket = null;
        EncryptedMessage responseMessage = null;
        byte[] encryptedFieldBytes;
    	long timestamp;
    	String clientUsername;
    	byte[] clientMasterKey;

        if ((subField != null)) {
            sendSubField = new SubField();
            // ServerID
            sendSubField.username = this.messageProcessor.getServer().getServerName();
            // Timestamp
            sendSubField.setTimestamp(ValidationHelper.getCurrentTimestamp());
            // Kms
            byte[] Kms = DHCipher.generateRandom128();
            sendSubField.sessionKey = Kms;

            // MST
    		timestamp = new Date().getTime();
            sendSessionTicket = new SessionTicket(subField.username, null, null, timestamp, timestamp + LOGIN_VALID_PERIOD);
            sendSessionTicket.setSessionKey(Kms);
            sendSessionTicket.setSessionIV(Kms);

            AESCipher aesCipher = new AESCipher(Kms, Kms);
            try {
                AESCipher.generateSessionKey(sendSessionTicket);
            } catch (NoSuchAlgorithmException e) {}

            EncryptedField sendField = new EncryptedField(
                    sendSessionTicket.getBytes(),
                    sendSubField.getBytes());
            
            AESCipher clientAESCipher = this.messageProcessor.getAESCipher();
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
                    EncryptedMessage.MSG_SEVER_RESPONSE, encryptedFieldBytes);
        }

        return responseMessage;
    }

    public EncryptedMessage processPKEYRequest (EncryptedField field) {
        SubField subField = new SubField(field.getEncryptedSubFieldBytes());
    	SubField sendSubField = null;
    	SessionTicket sendSessionTicket = null;
        EncryptedMessage responseMessage = null;
        byte[] encryptedFieldBytes;
    	long timestamp;
        byte[] Kms = null;

        if ((subField != null)) {
            sendSubField = new SubField();
            // ServerID
            sendSubField.username = this.messageProcessor.getServer().getServerName();
            // Timestamp
            sendSubField.setTimestamp(ValidationHelper.getCurrentTimestamp());
            // UserID2
            sendSubField.clientUsername = subField.clientUsername;

            // userID2 public key
            // Kccs
            
            ClientSessionInfo csInfo = this.messageProcessor.getClientMap().get(sendSubField.clientUsername);
            
            if (csInfo != null) {
                sendSubField.clientPublicKey = csInfo.getDHPublicKey();
                sendSubField.clientMessageSessionKey = csInfo.getDHSessionKey();
            }

            // MSGT2
            byte[] Kms2 = DHCipher.generateRandom128();
    		timestamp = new Date().getTime();
            sendSessionTicket = new SessionTicket(subField.username, null, null, timestamp, timestamp + LOGIN_VALID_PERIOD);
            sendSessionTicket.setSessionKey(Kms2);
            sendSessionTicket.setSessionIV(Kms2);

            AESCipher aesCipher = new AESCipher(Kms, Kms);
            try {
                AESCipher.generateSessionKey(sendSessionTicket);
            } catch (NoSuchAlgorithmException e) {}

            sendSubField.clientMessageSessionTicket = sendSessionTicket.getBytes();
            AESCipher clientAESCipher = this.messageProcessor.getAESCipher();

            EncryptedField sendField = new EncryptedField(null, sendSubField.getBytes());
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
                    EncryptedMessage.MSG_SEVER_RESPONSE, encryptedFieldBytes);
        }

        return responseMessage;
    }

    public EncryptedMessage processLogoutRequest (EncryptedField field) {
        SubField subField = new SubField(field.getEncryptedSubFieldBytes());
    	SubField sendSubField = null;
        EncryptedMessage responseMessage = null;
    	byte[] encryptedFieldBytes;
    	String clientUsername;
    	byte[] clientMasterKey;
    	long timestamp;
    	
    	clientUsername = new String(subField.username);
    	clientMasterKey = this.messageProcessor.getUserMasterKey(clientUsername);

        if ((subField != null)) {
            sendSubField = new SubField();

            
            AESCipher clientAESCipher = this.messageProcessor.getAESCipher();
            EncryptedField sendField = new EncryptedField(null, sendSubField.getBytes());
            encryptedFieldBytes = clientAESCipher.encryptBytes(sendField.getBytes());
            responseMessage = new EncryptedMessage(this.socket.getInetAddress(), this.socket.getPort(),
                    			EncryptedMessage.MSG_SEVER_RESPONSE, encryptedFieldBytes);
        }

        return responseMessage;
    }

    
    public EncryptedMessage processMessage(EncryptedMessage message) {
    	byte type = message.getType();
    	EncryptedMessage responseMessage = null;
   
    	switch (type) {
    		case EncryptedMessage.MSG_SEVER_LOGIN_ATTEMPT_REQUEST:
    			responseMessage = processLoginAttemptRequest(new EncryptedField(message.getMessage()));
    			break;
    		case EncryptedMessage.MSG_SEVER_REQUEST:
    			responseMessage = processRequest(new EncryptedField(message.getMessage()));
    			break;
    	}
    	
    	return responseMessage;
    }

    public void pause() {
        this.isRunning = false;
    }

    private long LOGIN_VALID_PERIOD = 10000; // 10 seconds
    private long MSG_VALID_PERIOD = 1800000; // 30 minutes = 1800 seconds
    
    private int type;

    private boolean isRunning;
    private ServerMessageProcessor messageProcessor;

    private static final int WORKER_INIT = 0x0;
    public static final int WORKER_SEND = 0x1;
    public static final int WORKER_RECV = 0x2;
    public static final int WORKER_BOTH = 0x3;
    
    private static final int MAX_BUFFER_SIZE = 4096;

    private Socket socket;
    private InputStream socketInputStream;
    private OutputStream socketOutputStream;
    
    private ServerDBHelper db;
    // TBD: Added a table for transaction
}
