/* 
 * EncryptedField.java
 *
 * @Date: 2014, March 22
 * 
 * @Note: This is the main class to encrypt the message
 * 
 * Message is serialized object
 * 
 * Session ticket is serialized object
 * 
 * IM | Version | Type | EncryptedField
 * 
 * 						 Type | EncryptedSessionTicket | EncryptedSubField
 *
 */

import java.io.*;
import java.security.*;

public class EncryptedField {
	// parse the bytes to class
	public EncryptedField(byte[] bytes) {
		ByteArrayInputStream bais = new ByteArrayInputStream(bytes);

		//System.out.println("EncryptedField length = " + bytes.length);
		this.encryptedSessionTicketBytes = new byte[SessionTicket.ENCRYPTED_SIZE];
		this.encryptedSubFieldBytes = new byte[bytes.length - SessionTicket.ENCRYPTED_SIZE];
		try {
			bais.read(this.encryptedSessionTicketBytes);
			bais.read(this.encryptedSubFieldBytes);
		} catch (IOException e) {}
		
		/*
		System.out.println("sessionTicekt len= " + this.encryptedSessionTicketBytes.length);
		System.out.println("subField len = " + this.encryptedSubFieldBytes.length);
		*/
	}

	public EncryptedField(byte[] encryptedSessionTicketBytes, byte[] encryptedSubFieldBytes) {
		this.encryptedSessionTicketBytes = encryptedSessionTicketBytes;
		this.encryptedSubFieldBytes = encryptedSubFieldBytes;

		/*
		if (this.encryptedSessionTicketBytes != null) {
			System.out.println("seesionTicket len = " + this.encryptedSessionTicketBytes.length);
		}
		if (this.encryptedSubFieldBytes != null) {
			System.out.println("subField len = " + this.encryptedSubFieldBytes.length);
		}
		*/
	}
	
	public byte[] getBytes() {
		byte[] bytes = new byte[SessionTicket.ENCRYPTED_SIZE + SubField.ENCRYPT_SIZE];
		
		if (this.encryptedSubFieldBytes != null) {
			System.arraycopy(this.encryptedSessionTicketBytes, 0, bytes, 0, this.encryptedSessionTicketBytes.length);
		}
		
		if (this.encryptedSubFieldBytes != null) {
			System.arraycopy(this.encryptedSubFieldBytes, 0, bytes, this.encryptedSessionTicketBytes.length, this.encryptedSubFieldBytes.length);
		}
		
		return bytes;
	}

	public byte[] getEncryptedSessionTicketByte() {
		return this.encryptedSessionTicketBytes;
	}
	
	public byte[] getEncryptedSubFieldBytes() {
		return this.encryptedSubFieldBytes;
	}
	
	private byte[] encryptedSessionTicketBytes;
	private byte[] encryptedSubFieldBytes;
}
