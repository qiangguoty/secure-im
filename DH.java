/**
 * Diffie-Hellman values & computations.
 * @author  Qiang Guo
 *
**/
//package IMUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DH {
    public BigInteger g = null;
    public BigInteger p = null;

    public static final int randomLength = 16;    // 16 bytes random number

    public DH(BigInteger g, BigInteger p) {
        this.g = g;
        this.p = p;
    }

    public static byte[] generateRandom() {
        /* Generate a secure 128-bit random number. */
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[randomLength];
        random.nextBytes(bytes);
        return bytes;
    }

    public BigInteger generateKey(BigInteger gamodp, BigInteger b) {
        /* Generate DH key by computing g^ab mod p */
        // raise gamodp to power of b
        return gamodp.modPow(b, this.p);

    }

    public BigInteger generateKey2(BigInteger a, BigInteger b) {
        /* Generate DH key by computing g^ab mod p */
        BigInteger gamodp = this.g.modPow(a, this.p);
        return gamodp.modPow(b, this.p);
    }

    public BigInteger getDHValue(BigInteger a) {
        /* Generate DH value by computing g^a mod p */
        return g.modPow(a, p);

    }
}