/**
 * ClientReceiveWorker.java
 * 
 * DatagramPacket -> EncryptedMessage -> Task
 *
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */
//package IMClient;

//import IMUtil.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

public class ClientReceiveWorker implements Runnable {
    public ClientReceiveWorker(ClientMessageProcessor processor) {
        this.messageProcessor = processor;
        this.isRunning = true;
    }

    // receive the socket and put it into receive queue
    @Override
    public void run() {
        byte[] recvBuffer = null;
        EncryptedMessage message = null;
        EncryptedMessage responseMessage = null;
        int recvLength;

        while(this.isRunning) {

            try {
                if (this.messageProcessor.getServerInputStream().available() > 0) {
                	recvBuffer = new byte[MAX_RECV_BUFFER];
                	recvLength = this.messageProcessor.getServerInputStream().read(recvBuffer);
                	if (recvLength > 0) {
                		message = new EncryptedMessage(this.messageProcessor.getServerIPAddress(),
                									   this.messageProcessor.getServerPort(), 
                									   recvBuffer);
                	}
                	
        			System.out.println("Recv " + message);
        			responseMessage = processMessage(message);
        			
        			if (responseMessage != null) {
        				System.out.println("Send " + responseMessage);
        				System.out.println("Send ack");
        				this.messageProcessor.getServerOutputStream().write(responseMessage.getBytes());
        			}
                }
                if (message != null) {
                    System.out.println("Recv " + message);
                    message = null;
                }
                
            } catch (IOException e) {}
        }
    }

    public EncryptedMessage processClientResponse(EncryptedField field) {
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
    		case SubField.MSG_TYPE_DH_ACK:
    			break;
    		case SubField.MSG_TYPE_MSG_ACK:
    			break;
    	}
    	
    	return null;
    }
    
    public EncryptedMessage processServerResponse(EncryptedField field) {
    	byte[] encryptedSessionTicketBytes = field.getEncryptedSessionTicketByte();
    	byte[] encryptedSubFieldBytes = field.getEncryptedSubFieldBytes();
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	SubField subField = null;
    	SessionTicket sessionTicket = null;
    	EncryptedMessage message = null;
    
    	AESCipher messageCipher = new AESCipher(this.messageProcessor.getClient().messageSessionKey,
    											this.messageProcessor.getClient().messageSessionKey);
    	// decrypt the subField
    	decryptedSubFieldBytes = messageCipher.decryptBytes(encryptedSessionTicketBytes);
    	subField = new SubField(decryptedSubFieldBytes);
    	
    	// check username
    	
    	// check timestamp
    	
    	// check hash Session Ticket
    	
    	
    	// handle the object
    	switch (subField.type) {
    		case SubField.MSG_TYPE_LIST_ACK:
    			//subField.userList;
    			
    			break;
    		case SubField.MSG_TYPE_MST_ACK:
    			// update session key
    			
    			// update session ticket
    			
    			break;
    		case SubField.MSG_TYPE_PKEY_ACK:
    			// update client 's session key
    		
    			// Dst User name
    			
    			// DstIp and Port
    			
    			// Dst Public key
    			
    			//this.messageProcessor.getClientSocket().send(packet);
    			break;
    			
    		case SubField.MSG_TYPE_LOGOUT_ACK:
    			break;
    	}
   
    	
    	return null;
    }
    
    public EncryptedMessage processLoginAttemptResponse(EncryptedField field) {
    	byte[] encryptedSessionTicketBytes = field.getEncryptedSessionTicketByte();
    	byte[] encryptedSubFieldBytes = field.getEncryptedSubFieldBytes();
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	SubField subField = null;
    	SessionTicket sessionTicket = null;
    	EncryptedMessage message = null;
    	AESCipher loginCipher = this.messageProcessor.getAESCipher();
   
    	System.out.println("handle response");
    	decryptedSubFieldBytes = loginCipher.decryptBytes(encryptedSubFieldBytes);
    	subField = new SubField(decryptedSubFieldBytes);
 
    	// seed is 32 byte
    	byte[] DHPublickey = loginCipher.decryptBytes(subField.seed);
    	this.messageProcessor.getClient().loginDHEncryptKey = DHCipher.generateEncryptKey(DHPublickey, 
    														  this.messageProcessor.getClient().loginDHNumber);
    	
    	this.messageProcessor.getClient().loginAttemptSessionKey = DHCipher.generateEncryptKey(DHPublickey, 
    	                                                           this.messageProcessor.getClient().loginDHNumber);
   
    	AESCipher lasCipher = new AESCipher(this.messageProcessor.getClient().loginAttemptSessionKey,
    										this.messageProcessor.getClient().loginAttemptSessionKey);
  
    	
    	// challenge is 32 byte
    	this.messageProcessor.getClient().clientAnsser = lasCipher.decryptBytes(subField.challenge);
    	this.messageProcessor.getClient().serverSessionTicket = subField.sessionTicket;
    
    	this.messageProcessor.isLoginAttemptSucceed = true;
    	// no return
    	return null;
    }
    
    public EncryptedMessage processLoginResponse(EncryptedField field) {
    	byte[] encryptedSessionTicketBytes = field.getEncryptedSessionTicketByte();
    	byte[] encryptedSubFieldBytes = field.getEncryptedSubFieldBytes();
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	SubField subField = null;
    	SessionTicket sessionTicket = null;
    	EncryptedMessage message = null;
    	AESCipher messageCipher = new AESCipher(this.messageProcessor.getClient().loginAttemptSessionKey,
    										this.messageProcessor.getClient().loginAttemptSessionKey);
    	
    	decryptedSessionTicketBytes = messageCipher.decryptBytes(encryptedSessionTicketBytes);
    	subField = new SubField(decryptedSessionTicketBytes);
    
    	// check username
    	
    	// check timestamp
    	
    	// check hash Session Ticket
    	
    	// handle the object
    	
    	// check type
    	if (subField.type == SubField.MSG_TYPE_LOGIN_ACK); {
    		this.messageProcessor.getClient().serverAnswer = subField.answer;
    		this.messageProcessor.getClient().setLoginSessionKey(subField.sessionKey);
    		this.messageProcessor.getClient().serverSessionTicket = subField.sessionTicket;
    	}
    	
    	this.messageProcessor.isLoginSucceed = true;
    	
    	// no return
    	return null;
    }
    
    public EncryptedMessage processLoginAuthenticationResponse(EncryptedField field) {
    	byte[] encryptedSessionTicketBytes = field.getEncryptedSessionTicketByte();
    	byte[] encryptedSubFieldBytes = field.getEncryptedSubFieldBytes();
    	byte[] decryptedSubFieldBytes = null;
    	byte[] decryptedSessionTicketBytes = null;
    	SubField subField = null;
    	SessionTicket sessionTicket = null;
    	EncryptedMessage message = null;
    	AESCipher messageCipher = new AESCipher(this.messageProcessor.getClient().loginSessionKey,
    										this.messageProcessor.getClient().loginSessionKey);
    	
    	decryptedSessionTicketBytes = messageCipher.decryptBytes(encryptedSessionTicketBytes);
    	subField = new SubField(decryptedSessionTicketBytes);
    	// check username
    	
    	// check timestamp
    	
    	// check hash Session Ticket
    	
    	// handle the object
    	
    	// check type
    	if (subField.type == SubField.MSG_TYPE_LOGIN_AUTH_ACK); {
       		this.messageProcessor.getClient().setMessageSessionKey(subField.sessionKey);
    		this.messageProcessor.getClient().serverSessionTicket = subField.sessionTicket;
    	}
    	
    	this.messageProcessor.isLoginAuthenticateSucceed = true;
    	// no return
    	return null;
    }
    
    public EncryptedMessage processMessage(EncryptedMessage message) {
    	byte type = message.getType();
    	EncryptedMessage responseMessage = null;
    	
    	switch (type) {
    		case EncryptedMessage.MSG_SEVER_RESPONSE:
    			responseMessage = processServerResponse(new EncryptedField(message.getMessage()));
    			break;
    		case EncryptedMessage.MSG_SEVER_LOGIN_RESPNOSE:
    			responseMessage = processLoginAttemptResponse(new EncryptedField(message.getMessage()));
    			break;
    	}
    	
    	return responseMessage;
    }
    
    public void pause() {
        this.isRunning = false;
    }

    public boolean validateLIST_ACK(EncryptedMessage msg) {
        boolean result = false;
        // Generate subfield
        EncryptedField eField = new EncryptedField(msg.getMessage());
        // SessionTicket sTicket = new SessionTicket(eField.getEncryptedSessionTicketByte());
        SubField sField = new SubField(eField.getEncryptedSubFieldBytes());

        // Validate ServerID
        if (Arrays.equals(sField.username, this.messageProcessor.serverID)) {
            if (ValidationHelper.validateTimestamp(sField.getTimestamp())) {
                result = true;
            }
        }

        return result;
    }

    public boolean validateMST_ACK(EncryptedMessage msg) {
        return validateLIST_ACK(msg);
    }

    public boolean validatePKEY_ACK(EncryptedMessage msg, byte[] targetUserID) {
        boolean result = false;
        // Generate subfield
        EncryptedField eField = new EncryptedField(msg.getMessage());
        // SessionTicket sTicket = new SessionTicket(eField.getEncryptedSessionTicketByte());
        SubField sField = new SubField(eField.getEncryptedSubFieldBytes());
        if ((validateLIST_ACK(msg)) && (Arrays.equals(targetUserID, sField.clientUsername))) {
            result = true;
        }
        return result;
    }

    public boolean validateDH_ACK(EncryptedMessage msg) throws NoSuchAlgorithmException {
        boolean result = false;
        // Generate subfield & sessionTicket
        EncryptedField eField = new EncryptedField(msg.getMessage());
        // SessionTicket sTicket = new SessionTicket(eField.getEncryptedSessionTicketByte());
        SubField sField = new SubField(eField.getEncryptedSubFieldBytes());

        // Validate timestamp
        if (ValidationHelper.validateTimestamp(sField.getTimestamp())) {
            // Validate session ticket hash
            if (Hasher.verifySHA256Hash(sField.sessionTicket, sField.hashSessionTicket)) {
                result = true;
            }
        }

        return result;
    }

    public boolean validateMSG_ACK(EncryptedMessage msg) throws NoSuchAlgorithmException {
        boolean result = false;
        // Generate subfield
        EncryptedField eField = new EncryptedField(msg.getMessage());
        // SessionTicket sTicket = new SessionTicket(eField.getEncryptedSessionTicketByte());
        SubField sField = new SubField(eField.getEncryptedSubFieldBytes());
        // Validate timestamp and session ticket hash
        if (validateDH_ACK(msg)) {
            // Validate message hash
            if (Hasher.verifySHA256Hash(sField.message, sField.hashMessage)) {
                result = true;
            }
        }
        return result;
    }

    public boolean validateLOGOUT_ACK(EncryptedMessage msg) {
        return validateLIST_ACK(msg);
    }

    private boolean isRunning;
    private ClientMessageProcessor messageProcessor;
    
    private long LOGIN_VALID_PERIOD = 10000; // 10 seconds
    private long MSG_VALID_PERIOD = 1800000; // 30 minutes = 1800 seconds
    
    private static final int MAX_RECV_BUFFER = 4096;
    private static final int MAX_SLEEP_MILISECONDS = 100;
}
