// This is a partial implementation for Schornn Keys with Fiat-Shamir
// to accomplish a non-interactive Protocol for the Hashed Secret Key
//
// Structure taken from github.com/vonderhaar/6857-PasswordManager
// but using Bouncycastle
package net.aochain;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;

public class SchnorrVerifier {

	public static boolean verify(ECPoint genPoint, ECPoint publicKey, ECPoint V, BigInteger r, BigInteger userId)
			throws IOException, NoSuchAlgorithmException {

		BigInteger c = makeChallenge(genPoint, publicKey, V, userId);

		// This calculates V = rG + aG*c -> V = rG + A*c
		ECPoint testV = (genPoint.multiply(r)).add(publicKey.multiply(c));

		// Write y/n to txt file so C code can see what the response is
		boolean output = V.equals(testV);
		return output;
	}

	// c = H(G|| V || A || UserID || OtherInfo)
	private static BigInteger makeChallenge(ECPoint genPoint, ECPoint publicKey, ECPoint V, BigInteger userID)
			throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		List<Byte> toHashList = new ArrayList<>();
		addByteArray(toHashList, genPoint.getXCoord().getEncoded());
		addByteArray(toHashList, genPoint.getYCoord().getEncoded());
		addByteArray(toHashList, V.getXCoord().getEncoded());
		addByteArray(toHashList, V.getYCoord().getEncoded());
		addByteArray(toHashList, publicKey.getXCoord().getEncoded());
		addByteArray(toHashList, publicKey.getYCoord().getEncoded());
		addByteArray(toHashList, userID.toByteArray());

		byte[] toHash = new byte[toHashList.size()];
		for (int i = 0; i < toHashList.size(); i++) {
			toHash[i] = toHashList.get(i).byteValue();
		}
		BigInteger c = new BigInteger(digest.digest(toHash));
		return c.abs(); // overflow, so take absolute value
	}

	private static BigInteger makeChallenge(ECPoint ecPoint)
			throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		List<Byte> toHashList = new ArrayList<>();
		addByteArray(toHashList, ecPoint.getXCoord().getEncoded());
		addByteArray(toHashList, ecPoint.getYCoord().getEncoded());

		byte[] toHash = new byte[toHashList.size()];
		for (int i = 0; i < toHashList.size(); i++) {
			toHash[i] = toHashList.get(i).byteValue();
		}
		BigInteger c = new BigInteger(digest.digest(toHash));
		return c.abs(); // overflow, so take absolute value
	}
	
	private static void addByteArray(List<Byte> aryList, byte[] ary) {
		for (byte b : ary) {
			aryList.add(b);
		}
	}
}
