import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Hasher {

    public static byte[] bytesToSHA256 (byte[] bytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes);
        return md.digest();
    }

    public static boolean verifySHA256Hash (byte[] data, byte[] hash) throws NoSuchAlgorithmException {
        boolean result = false;
        byte[] realHash = bytesToSHA256(data);
        if (Arrays.equals(realHash, hash)) {
            result = true;
        }
        return result;
    }
}