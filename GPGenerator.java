//package IMUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class GPGenerator {
	public static void main(String[] args) {
		BigInteger[] bi = new BigInteger[2];
	
		bi = gen(127, 127);
		
		System.out.println(bi[0]);
		System.out.println(bi[1]);
		
		System.out.println(bi[0].toByteArray().length);
		System.out.println(bi[1].toByteArray().length);
		
	}
    public static BigInteger[] gen(int gLength, int pLength) {
        SecureRandom random = new SecureRandom();
        BigInteger[] result = new BigInteger[2];
        boolean isPrime = false;
        while (!isPrime) {
            BigInteger g = BigInteger.probablePrime(gLength, random);
            BigInteger p = BigInteger.probablePrime(pLength, random);
            // Primility test
            if (MillerRabin.millerRabin(g, 7) && MillerRabin.millerRabin(p, 7)) {
                isPrime = true;
                result[0] = g;
                result[1] = p;
            }
        }
        return result;
    }
}