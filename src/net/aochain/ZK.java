package net.aochain;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.bouncycastle.math.ec.ECPoint;

import Common.Commitments.Open;

public class ZK {
	private BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
	private ECPoint g1;
	private ECPoint g2;
	public ECPoint g1x;
	public ECPoint y1x;
	public BigInteger w1;
	public ECPoint g1w;
	public ECPoint y1w;
	public BigInteger chall1;
	public BigInteger resp1;
	public ECPoint g2x;
	public ECPoint y2x;
	public BigInteger w2;
	public ECPoint g2w;
	public ECPoint y2w;
	public BigInteger chall2;
	public BigInteger resp2;

	public ZK(ECPoint g1, ECPoint g2, ECPoint g1x, ECPoint g2x, ECPoint y1x, ECPoint y2x, BigInteger w1, BigInteger w2, ECPoint g1w,
			ECPoint g2w, ECPoint y1w, ECPoint y2w, BigInteger chall1, BigInteger resp1, BigInteger chall2,
			BigInteger resp2) throws NoSuchAlgorithmException {
		this.g1  = g1;
		this.g2  = g2;
		this.g1x = g1x;
		this.g2x = g2x;
		this.y1x = y1x;
		this.y2x = y2x;
		this.w1 = w1;
		this.g1w = g1w;
		this.y1w = y1w;
		this.w2 = w2;
		this.g2w = g2w;
		this.y2w = y2w;
		this.chall1 = chall1;
		this.resp1 = resp1;
		this.chall2 = chall2;
		this.resp2 = resp2;
	}

	public ZK(ECPoint g1, ECPoint g2, ECPoint y1, ECPoint y2, ECPoint Token1, ECPoint Token2, BigInteger x1,
			BigInteger x2) throws NoSuchAlgorithmException {
		this.g1x = g1.multiply(x1);
		this.g2x = g2.multiply(x2);
		this.y1x = y1.multiply(x1);
		this.y2x = y2.multiply(x2);
		this.w1 = chooseRandom(this.N);
		this.g1w = g1.multiply(w1);
		this.y1w = y1.multiply(w1);
		this.w2 = chooseRandom(this.N);
		this.g2w = g2.multiply(w2);
		this.y2w = y2.multiply(w2);
		this.chall1 = makeChallenge(g1, Token1);
		this.resp1 = this.w1.add(x1.multiply(this.chall1));
		this.chall2 = makeChallenge(g2, Token2);
		this.resp2 = this.w2.add(x2.multiply(this.chall2));
	}

	private BigInteger chooseRandom(BigInteger max) {
		SecureRandom random = new SecureRandom();
		return new BigInteger(max.toString(2).length(), random).mod(max).add(BigInteger.ONE);
	}

	private static BigInteger makeChallenge(ECPoint genPoint, ECPoint Token) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		List<Byte> toHashList = new ArrayList<>();
		addByteArray(toHashList, genPoint.getXCoord().getEncoded());
		addByteArray(toHashList, genPoint.getYCoord().getEncoded());
		addByteArray(toHashList, Token.getXCoord().getEncoded());
		addByteArray(toHashList, Token.getYCoord().getEncoded());

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