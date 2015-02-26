/*
 * DHCipher.java
 *
 * @author: Jingdi Ren
 * @date:   Feb 08, 2014
 * @notes:
 *
 */

//package IMUtil;

import java.math.*;
import java.util.*;
import java.security.SecureRandom;

public class DHCipher {
	public static void main(String[] args) {
	
		for (long i = 0; i < 2000000; i++) {
		byte[] num1 = generateRandom128();
		byte[] num2 = generateRandom128();
	
		System.out.println(new BigInteger(num2));
		System.out.println(new BigInteger(num1));
		//System.out.println(Arrays.equals(num1, num2));
		
		byte[] dhnum1 = generateDHPublicKey(num1);
		byte[] dhnum2 = generateDHPublicKey(num2);
		
		byte[] dh1 = generateEncryptKey(dhnum1, num2);
		byte[] dh2 = generateEncryptKey(dhnum2, num1);
		if (Arrays.equals(dh1, dh2) == false) {
			System.out.println("Test Failed");
			break;
		}
		}
	}
	
	// generate DH number
	public static byte[] generateRandom128() {
		return DH.generateRandom();
	}
	
	// generate DH public key
	public static byte[] generateDHPublicKey(byte[] a) {
		DH dh = new DH(DHg, DHp);
		
		return dh.getDHValue(new BigInteger(a)).toByteArray();
	}

	public static byte[] generateEncryptKey(byte[] gmodp, byte[] b) {
		DH dh = new DH(DHg, DHp);
		
		return dh.generateKey(new BigInteger(gmodp), new BigInteger(b)).toByteArray();
	}
	
	
	private static BigInteger DHg = new BigInteger(new String("113960964315680610745594676374642391473"));
	private static BigInteger DHp = new BigInteger(new String("119373729006682616389229813005838647219"));
}
