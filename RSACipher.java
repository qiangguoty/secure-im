/* 
 * RSACipher.java
 *
 * @author: Jingdi Ren
 * @date:   Feb 08, 2014
 *
 * @notes: RSACipher contains the following functionality:
 *
 * (1) generate key pair
 * (2) encrypt the bytes with public key
 * (3) decrypt the bytes with private key
 * (4) sign the bytes with private key
 * (5) verify the bytes with public key
 *
 */

//package IMUtil;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class RSACipher {
    /* parse the parameters */
    public int parseParameters(String[] args) {
        if (args.length != 1) {
            return -1;
        }
        this.fileName = args[0];
        this.publicKeyFileName = args[0] + ".pub";
        this.privateKeyFileName = args[0] + ".priv";
        return 0;
    }

    /* set the encrypt key file name */
    public void setEncryptKeyFileName(String file) {
        this.encryptKeyFileName = file;
    }

    /* set the decrypt key file name */
    public void setDecryptKeyFileName(String file) {
        this.decryptKeyFileName = file;
    }

    /* set the verify key file name */
    public void setVerifyKeyFileName(String file) {
        this.verifyKeyFileName = file;
    }
    
    /* set the sign key file name */
    public void setSignKeyFileName(String file) {
        this.signKeyFileName = file;
    }

    /* generate the key pair */
    public void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

        try {
            /* Write key to file */
            FileOutputStream pubOut = new FileOutputStream(this.publicKeyFileName);
            FileOutputStream privOut = new FileOutputStream(this.privateKeyFileName);
            
            pubOut.write(publicKey.getEncoded());
            privOut.write(privateKey.getEncoded());

            /* flush the buffer */
            pubOut.flush();
            privOut.flush();
        } catch (Exception e) {
            System.out.println("RSACipher: failed to generate key file");
        }
    }

    /* encrypt the bytes */
    public byte[] encryptBytes(byte[] bytes) throws Exception {
        try {
            /* read the file */
            byte[] keyBytes = readFile(this.encryptKeyFileName);
            /* get the key */
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key publicKey = keyFactory.generatePublic(keySpec);

            /* encrypt the bytes */
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(bytes);

        } catch (IOException e) {
            System.out.println("RSACipher: failed to open the key file to encrypt");
        }

        return null;
    }

    /* decrypt the bytes */
    public byte[] decryptBytes(byte[] bytes) throws Exception {
        try {
            /* read the file */
            byte[] keyBytes = readFile(this.decryptKeyFileName);

            /* get the key */
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            Key privateKey = keyFactory.generatePrivate(keySpec);

            /* decrypt the bytes */
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(bytes);

        } catch (IOException e) {
            System.out.println("RSACipher: failed to open the key file to decrypt");
        }

        return null;
    }

    /* sign the bytes */
    public byte[] signBytes(byte[] bytes) throws Exception {
        /* read the file */
        byte[] keyBytes = readFile(this.signKeyFileName);

        /* get the key */
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        /* sign the bytes */
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(bytes);
        return signature.sign();
    }

    /* verify the bytes */
    public boolean verifyBytes(byte[] bytes, byte[] signBytes) throws Exception {
        /* read the file */
        byte[] keyBytes = readFile(this.verifyKeyFileName);

        /* get the key */
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        /* verify the bytes */
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(bytes);
        return signature.verify(signBytes);
    }

    /* read the file with the given file name */
    private byte[] readFile(String fileName) throws IOException {
        InputStream inputStream = new FileInputStream(fileName);
        byte[] bytes = new byte[inputStream.available()];
        inputStream.read(bytes);
        inputStream.close();

        return bytes;
    }

    /* tostring functionality */
    public String toString() {
        String str = "RSACipher {fileName: " + this.fileName +
                     " publicKeyFileName: " + this.publicKeyFileName +
                     " privateKeyFileName: " + this.privateKeyFileName +
                     "}";
        return str;
    }

    public static void main(String[] args) {
        RSACipher rsa = new RSACipher();
        if (rsa.parseParameters(args) != 0) {
            System.out.println("java RSACipher <filename>");
            System.exit(-1);
        }
        try {
            rsa.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /* user given file name for the public and private key */
    String fileName;
    /* public key name is fileName.pub */
    String publicKeyFileName;
    /* private key name is fileName.priv */
    String privateKeyFileName;
    
    private String encryptKeyFileName;
    private String decryptKeyFileName;
    private String signKeyFileName;
    private String verifyKeyFileName;

    public static final int KEY_SIZE = 2048;
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM="MD5withRSA";
}
