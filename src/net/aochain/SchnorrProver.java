// This is a partial implementation for Schornn Keys with Fiat-Shamir
// to accomplish a non-interactive Protocol for the Hashed Secret Key
//
// Structure taken from github.com/vonderhaar/6857-PasswordManager
// but using Bouncycastle
package net.aochain;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.util.ArrayList;

public class SchnorrProver {

	private BigInteger privateKey;
	private ECPoint publicKey;
	private BigInteger userID;
	private BigInteger littleV;
	private ECPoint bigV;
	private BigInteger littleR;
	private BigInteger c;

	// define generator point and big prime n
	private BigInteger xCoord = new BigInteger(
			//"77da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4",16);
			"f0da850a6b7c61a66cdd43ac7529affb1aaf2111a10a5e15dd8619fef0f5b754", 16);
	private BigInteger yCoord = new BigInteger(
			//"a7094ec08a38b3befe52360b356573d2af2806a6eab38f2b323b428565ffe0e5",16);
			"6c8a8967fbbb58983ed41b0672766f7017a4f01ee9dc27e3d3474179ae4817f1", 16);
	private ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
	private SecP256K1Curve ecCurve = (SecP256K1Curve) ecSpec.getCurve();
	private ECPoint genPoint = ecCurve.createPoint(xCoord, yCoord);
	// ECCurve.COORD_AFFINE
	// Group Order parameter
	private BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
	// Subgroup Order parameter
	private BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

	public SchnorrProver(BigInteger userID) throws NoSuchAlgorithmException {
		this.userID = userID;
		chooseKeys();
		
		// Choses a random v and computes a V from sec256k1 and base point
		computeV();
		
		// Creates the non interactive c (Hashing)
		// c = H(G|| V || A || UserID || ... OtherInfo)
		// ---> G is genPoint with preset (x,y)
		// A is the Public Key
		// userId is the Account Address
		this.c = makeChallenge(genPoint, publicKey, bigV, userID);
		// This calculates r = v - a*c
		// ----> v was the random number found in computeV()
		// a is the private Key
		// c is the non-interactive c found with makeChallenge
		computeR();
	}

	// Getters
	public ECPoint getGenPoint() {
		return this.genPoint;
	}

	public BigInteger getSecretKey() {
		return this.privateKey;
	}

	public ECPoint getPublicKey() {
		return this.publicKey;
	}

	public ECPoint getV() {
		return this.bigV;
	}

	public BigInteger getR() {
		return this.littleR;
	}

	public BigInteger getOrder() {
		return this.P;
	}
	public BigInteger getSubOrder() {
		return this.N;
	}

	public BigInteger getC() {
		return this.c;
	}

	public String toString() {
		StringBuilder output = new StringBuilder();
		output.append(this.getGenPoint().getXCoord().toString());
		output.append(",");
		output.append(this.getGenPoint().getYCoord().toString());
		output.append("|");
		output.append(this.getPublicKey().getXCoord().toString());
		output.append(",");
		output.append(this.getPublicKey().getYCoord().toString());
		output.append("|");
		output.append(this.privateKey.toString());
		output.append("|");
		output.append(this.getV().getXCoord().toString());
		output.append(",");
		output.append(this.getV().getYCoord().toString());
		output.append("|");
		output.append(this.getR().toString());
		output.append("|");
		output.append(this.getOrder().toString(16));
		return output.toString();
	}

	private void chooseKeys() {
		// choose private key between 1 and n-1
		this.privateKey = chooseRandom(this.N);
		this.publicKey = this.genPoint.multiply(this.privateKey);
	}

	private void computeV() {
		// choose v between 1 and n-1
		this.littleV = chooseRandom(this.N);
		this.bigV = this.genPoint.multiply(this.littleV);
	}

	private void computeR() {
		this.littleR = this.littleV.subtract(this.privateKey.multiply(this.c)).mod(this.N);
	}

	private BigInteger chooseRandom(BigInteger max) {
		SecureRandom random = new SecureRandom();
		return new BigInteger(max.toString(2).length(), random).mod(max).add(BigInteger.ONE);
	}

	// c = H(G|| V || A || UserID || ... OtherInfo)
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

	private static void addByteArray(List<Byte> aryList, byte[] ary) {
		for (byte b : ary) {
			aryList.add(b);
		}
	}
}
