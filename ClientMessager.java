/**
 * ClientMessager.java
 * 
 * Used to message between clients
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

public class ClientMessager implements Runnable {
    public ClientMessager(ClientMessageProcessor processor) {
        this.messageProcessor = processor;
        this.isRunning = true;
    }

    // receive the socket and put it into receive queue
    @Override
    public void run() {
    	DatagramPacket packet = null;
        EncryptedMessage message = null;
        EncryptedMessage responseMessage = null;
        int recvLength;
        byte[] recvBuffer = null;

        while(this.isRunning) {
            try {
               	recvBuffer = new byte[MAX_RECV_BUFFER];
               	packet = new DatagramPacket(recvBuffer, recvBuffer.length);
               	this.messageProcessor.getClientSocket().receive(packet);
               	
               	message = new EncryptedMessage(this.messageProcessor.getServerIPAddress(),
               									   this.messageProcessor.getServerPort(), 
               									   packet.getData());
               	
        		System.out.println("Recv " + message);
        		responseMessage = processMessage(message);
        		
        		if (responseMessage != null) {
        			System.out.println("Send " + responseMessage);
        			System.out.println("Send ack");
        			this.messageProcessor.getServerOutputStream().write(responseMessage.getBytes());
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
    	
    	switch (subField.type) {
    		case SubField.MSG_TYPE_DH_ACK:
    			break;
    			
    		case SubField.MSG_TYPE_MSG_ACK:
    		
    			// finish send the client
    			this.messageProcessor.currentDstClient = null;
    			break;
    	}
    	
    	return null;
    }
    
    public EncryptedMessage processMessage(EncryptedMessage message) {
    	byte type = message.getType();
    	EncryptedMessage responseMessage = null;
    
    	switch (type) {
    		case EncryptedMessage.MSG_CLIENT_RESPONSE:
    			responseMessage = processClientResponse(new EncryptedField(message.getMessage()));
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
