package Common;

import java.math.BigInteger;
import java.util.Random;

public class Util {
	public static BigInteger randomFromZn(BigInteger n, Random rand) {
		BigInteger result;
		do {
			result = new BigInteger(n.bitLength(), rand);
			// check that it is in Zn
		} while (result.compareTo(n) != -1);
		return result;
	}
}
