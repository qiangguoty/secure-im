/*
 * AESCipher.java
 *
 */

import java.io.*;
import java.security.*;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.*;

public class AESCipher {
	public static void main(String[] args) {
		AESCipher aes = new AESCipher();
		
		aes.generateKey(new String("password").getBytes());
		byte[] bytes = new String("123").getBytes();
		byte[] ebytes = aes.encryptBytes(bytes);
		
		System.out.println(ebytes.length);
		System.out.println(Arrays.equals(bytes, aes.decryptBytes(ebytes)));
	}
	
    public AESCipher() {
        this.keyGenerated = false;
        this.encryptKey = null;
        this.IV = null;
    }
    
    public AESCipher(byte[] keyBytes, byte[] IVBytes) {
        this.keyGenerated = true;
        this.encryptKey = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        this.IV =new IvParameterSpec(IVBytes);
    }

    public static void generateSessionKey(SessionTicket sessionTicket) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom random = new SecureRandom();

        /* generate the key */
        keygen.init(DEFAULT_CIPHER_KEY_SIZE, random);
        Key secretKey = keygen.generateKey();

        sessionTicket.setSessionKey(secretKey.getEncoded());
        sessionTicket.setSessionIV(random.generateSeed(IV_BYTE));
    }
    
    /* generate key */
    public void generateKey128() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom random = new SecureRandom();

        /* generate the key */
        keygen.init(16, random);

        this.encryptKey = keygen.generateKey();
        this.IV = new IvParameterSpec(random.generateSeed(IV_BYTE));
        this.keyGenerated = true;
    }   
    
    /* generate key */
    public void generateKey256() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(KEY_ALGORITHM);
        SecureRandom random = new SecureRandom();

        /* generate the key */
        keygen.init(32, random);

        this.encryptKey = keygen.generateKey();
        this.IV = new IvParameterSpec(random.generateSeed(IV_BYTE));
        this.keyGenerated = true;
    }   
    
    // given password, generate the master key
    public void generateKey(byte[] password) {
    	try {
    	MessageDigest md = MessageDigest.getInstance(MD_ALGORITHM);
    	
    	md.update(password);
        this.encryptKey = new SecretKeySpec(md.digest(), KEY_ALGORITHM);
        this.IV =new IvParameterSpec(Arrays.copyOf(md.digest(), IV_BYTE)); 
 
    	} catch (NoSuchAlgorithmException e) {
    		System.out.println("failed to generate key");
    	}
        this.keyGenerated = true;
    }

    /* check if the key is generated */
    public boolean isKeyGenerated() {
        return this.keyGenerated;
    }

    public byte[] getInitializationVector() {
    	return this.ivBytes;
    }
    
    public byte[] encryptBytes(byte[] inputBytes) {
    	ByteArrayInputStream bais = new ByteArrayInputStream(inputBytes);
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    	try {
    		encrypt(bais, baos);
    	} catch (Exception e) {
    		//e.printStackTrace();
    		return null;
    	}
    	
    	return baos.toByteArray();
    }
    
    public byte[] decryptBytes(byte[] inputBytes) {
    	ByteArrayInputStream bais = new ByteArrayInputStream(inputBytes);
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    	try {
    		decrypt(bais, baos);
    	} catch (Exception e) {
    		//e.printStackTrace();
    		return null;
    	}
    	
    	return baos.toByteArray();
    }
    
    public void encrypt(InputStream in, OutputStream out) throws Exception {
        crypt(in, out, Cipher.ENCRYPT_MODE);
    }
    
    public void decrypt(InputStream in, OutputStream out) throws Exception {
        crypt(in, out, Cipher.DECRYPT_MODE);
    }

    private void crypt(InputStream in, OutputStream out, int mode) throws Exception {
        Cipher aesCipher;
        int inBlockSize;
        int outBlockSize;
        byte[] inBytes;
        byte[] outBytes;
        int inLength;
        int outLength;
        boolean isEndOfStream = false;
        int keyLength;

        /* Initialze the cipher */
        aesCipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
        aesCipher.init(mode, this.encryptKey, this.IV);

        /* set the block size */
        inBlockSize = aesCipher.getBlockSize();
        outBlockSize = aesCipher.getOutputSize(inBlockSize);

        inBytes = new byte[inBlockSize];
        outBytes = new byte[outBlockSize];
        inLength = 0;
       
        while (!isEndOfStream) {
            inLength = in.read(inBytes);
            if (inLength == inBlockSize) {
                outLength = aesCipher.update(inBytes, 0, inBlockSize, outBytes);
                out.write(outBytes, 0, outLength);
            }
            else {
                isEndOfStream = true;
            }
        }

        /* parse the remain bytes */
        if (inLength > 0) {
            outBytes = aesCipher.doFinal(inBytes, 0, inLength);
        }
        else {
            outBytes = aesCipher.doFinal();
        }
        out.write(outBytes);
        out.flush();
    }

    private Key encryptKey;
    private IvParameterSpec IV;
 
    private byte[] ivBytes;
    private boolean keyGenerated;
    private static final String MD_ALGORITHM = "SHA-256";
    private static final String KEY_ALGORITHM = "AES";
    private static final int BYTE_BIT = 8;
    private static final int DEFAULT_CIPHER_KEY_SIZE = 128;
    private static final int KEY_BYTE = DEFAULT_CIPHER_KEY_SIZE / BYTE_BIT;
    private static final int IV_BYTE = 16;
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
}
