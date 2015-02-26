
import java.io.IOException;
import java.lang.String;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.io.*;

class ServerDBHelper {
	public static byte[] getUserMasterKey(String username, AESCipher aesCipher) {
        HashMap<String, String> result = new HashMap<String, String>();
        byte[] randomBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(randomBytes);

        byte[] encrypted = FileHelper.readBytes(DB_FILE_NAME);
        byte[] decrypted = aesCipher.decryptBytes(encrypted);
        System.out.println(decrypted.length);

        // split counter, data and hash
        
        byte[] data = new byte[65536 + 2];
        System.arraycopy(decrypted, 0, data, 0, 65536 + 2);
        short counter = (short) ((short)((data[1] & 0xFF) << 8) + (short)(data[0] & 0xFF));
        System.out.println(counter);
        byte[] hash = new byte[32];
       
        System.arraycopy(decrypted, 2 + 65536, hash, 0, 32);
       
        // verify hash
        try {
        if (Hasher.verifySHA256Hash(data, hash) == true) {
            // start from 2 to length of counter
            // each username + password pair: 64 Bytes
            // add kv pair to result
            for (int i = 0; i < counter; i++) {
                byte[] pair = Arrays.copyOfRange(data, 2 + i * 64, 2 + (i + 1) * 64);
                String name = new String(Arrays.copyOfRange(pair, 0, 32));
                if (name.compareTo(username) == 0) {
                	return Arrays.copyOfRange(pair, 32, 48);
                }	
            }
        }
        else {
        	System.out.println("hash doesn't match");
        }
        } catch (NoSuchAlgorithmException e) {
        	return randomBytes;
        }

        return randomBytes;
	}

	public static boolean checkDB(AESCipher aesCipher) throws IOException, NoSuchAlgorithmException {
	    HashMap<String, String> result = new HashMap<String, String>();

	    byte[] encrypted = FileHelper.readBytes(DB_FILE_NAME);
	    byte[] decrypted = aesCipher.decryptBytes(encrypted);

	    // split counter, data and hash
	    byte[] data = new byte[65536 + 2];
	    System.arraycopy(decrypted, 0, data, 0, 65536 + 2);
	    short counter = (short) ((short)((data[1] & 0xFF) << 8) + (short)(data[0] & 0xFF));
	    byte[] hash = new byte[32];
	   
	    System.arraycopy(decrypted, 2 + 65536, hash, 0, 32);
	   
	    // verify hash
	    return Hasher.verifySHA256Hash(data, hash);
	}
	
    public static HashMap<String, String> readDB(AESCipher aesCipher) throws IOException, NoSuchAlgorithmException {
        HashMap<String, String> result = new HashMap<String, String>();

        byte[] encrypted = FileHelper.readBytes(DB_FILE_NAME);
        byte[] decrypted = aesCipher.decryptBytes(encrypted);
        
        if (decrypted == null) {
        	return null;
        }

        /*
        System.out.println(encrypted.length);
        System.out.println(decrypted.length);
        */
        byte[] data = new byte[65536 + 2];
        System.arraycopy(decrypted, 0, data, 0, 65536 + 2);
        short counter = (short) ((short)((data[1] & 0xFF) << 8) + (short)(data[0] & 0xFF));
        byte[] hash = new byte[32];
       
        System.arraycopy(decrypted, 2 + 65536, hash, 0, 32);
       
        // verify hash
        if (Hasher.verifySHA256Hash(data, hash) == true) {
            // start from 2 to length of counter
            // each username + password pair: 64 Bytes
            // add kv pair to result
            for (int i = 0; i < counter; i++) {
                byte[] pair = Arrays.copyOfRange(data, 2 + i * 64, 2 + (i + 1) * 64);
                String username = new String(Arrays.copyOfRange(pair, 0, 32));
                String password = new String(Arrays.copyOfRange(pair, 32, 48));
                /*
                System.out.println("name = " + username);
                System.out.println(new String(aesCipher.decryptBytes(Arrays.copyOfRange(pair, 32, 48))));
                */
                result.put(username, password);
            }
        }
        else {
        	return null;
        }

        return result;
    }

    public static void resetDB(AESCipher aesCipher) throws IOException, NoSuchAlgorithmException {
        // 64KB random bytes
        byte[] randomBytes = new byte[65536];
        Random random = new Random();
        random.nextBytes(randomBytes);
        
        byte[] strName;
        byte[] strkeys;
        byte[] name;
        byte[] key;
        
        // preload the data
        for (int i = 0; i < 10; i++) {
        	strName = new String("u" + i).getBytes();
        	strkeys = aesCipher.encryptBytes(new String("p" + i).getBytes());
        	name = new byte[32];
        	key = new byte[32];
        	
        	System.arraycopy(strkeys, 0, key, 0, strkeys.length);
        	System.arraycopy(strName, 0, name, 0, strName.length);
        	
        	System.arraycopy(name, 0, randomBytes, i * 64, 32);
        	System.arraycopy(key, 0, randomBytes, i * 64 + 32, 32);
        }
        
        // 2B Counter
        short counter = 10;
        byte[] counterBytes = new byte[2];
        counterBytes[0] = (byte)(counter & 0xff);
        counterBytes[1] = (byte)((counter >> 8) & 0xff);

        // 32B Hash of counter + random bytes
        byte[] data = new byte[counterBytes.length + randomBytes.length];
        System.arraycopy(counterBytes, 0, data, 0, counterBytes.length);
        System.arraycopy(randomBytes, 0, data, counterBytes.length, randomBytes.length);
        byte[] hash = Hasher.bytesToSHA256(data);
        // All
        byte[] all = new byte[data.length + hash.length];
        System.arraycopy(data, 0, all, 0, data.length);
        System.arraycopy(hash, 0, all, data.length, hash.length);

        // Encrypt with AESCipher
        byte[] encrypted = aesCipher.encryptBytes(all);
        
        //System.out.println(Arrays.equals(aesCipher.decryptBytes(encrypted), all));
       
        //byte[] decryptedHash = new byte[32];
        
        //System.arraycopy(aesCipher.decryptBytes(encrypted), 65536 + 2, decryptedHash, 0, 32);
        //System.out.println(Arrays.equals(hash, decryptedHash));
        
        // Write all to file
        FileHelper.writeBytes(encrypted, DB_FILE_NAME);
    }

    private static AESCipher aes = new AESCipher();
    private static String DB_FILE_NAME = "master.db";
}