//package IMUtil;

import java.math.BigInteger;

public class DHTest {

    public static void main(String[] args) {
        // get g and p
        BigInteger[] gp = GPGenerator.gen(5, 10);
        BigInteger g = gp[0];
        BigInteger p = gp[1];
        System.out.println("g:" + g);
        System.out.println("p:" + p);

        DH dh = new DH(g,p);

        // random gen
        BigInteger a = new BigInteger(dh.generateRandom()).abs();
        System.out.println("random a:" + a);
        BigInteger b = new BigInteger(dh.generateRandom()).abs();
        System.out.println("random b:" + b);



        // ga mod p
        BigInteger gamodp = dh.getDHValue(a);
        System.out.println("ga mod p:" + gamodp);
        BigInteger gbmodp = dh.getDHValue(b);
        System.out.println("gb mod p:" + gbmodp);

        // g ab mod p
        BigInteger gabmodp = dh.generateKey(gamodp, b);
        System.out.println("gab mod p (1):" + gabmodp);

        gabmodp = dh.generateKey2(a,b);
        System.out.println("gab mod p (2):" + gabmodp);

    }
}