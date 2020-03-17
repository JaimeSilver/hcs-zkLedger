package net.aochain;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import Common.Commitments.Open;
import Common.Commitments.PedersenPublicFile;
import Common.Commitments.PedersenPublicParams;

public class Pedersen {
	private static PedersenPublicParams params;
	// Order (Q) P=RQ+1 ->P-1=RQ
	// where is P =
	// 115792089237316195423570985008687907853269984665640564039457584007908834671663
	// from 2^256 �2^32 �2^9 �2^8 �2^7 �2^6 �2^4 �1
	//
	// Entry in WolframAlpha to find Prime Factorization:
	// (https://www.wolframalpha.com/input/?i=115792089237316195423570985008687907853269984665640564039457584007908834671662)
	//
	// =>
	// 2�3�7�13441�205115282021455665897114700593932402728804164701536103180137503955397371
	final static BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
	final static BigInteger Q = new BigInteger(
			"205115282021455665897114700593932402728804164701536103180137503955397371");
	private final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
	private final SecP256K1Curve ecCurve = (SecP256K1Curve) ecSpec.getCurve();
	private ECPoint commitment;
	private Open open;

	public Pedersen() {
		this.commitment = null;
		this.open = null;
	}

	public Pedersen(ECPoint commitment, Open open) {
		this.commitment = commitment;
		this.open = open;
	}

	public ECPoint getCommitment() {
		return commitment;
	}

	public Open getOpen() {
		return open;
	}

	public void init(PedersenPublicParams p) {
		params = p;
	}

	public void initBase(BigInteger gxCoord, BigInteger gyCoord, BigInteger hxCoord, BigInteger hyCoord, int number,
			String filename, String keys) throws NoSuchAlgorithmException {
		ECPoint G = ecCurve.createPoint(gxCoord, gyCoord);
		ECPoint H = ecCurve.createPoint(hxCoord, hyCoord);
		ECPoint[] BanksPublicKeys = new ECPoint[number];
		BigInteger[] BanksSecretKeys = new BigInteger[number];

		for (int i = 0; i < number; i++) {
			SchnorrProver prover = new SchnorrProver(BigInteger.valueOf(i));
			BanksPublicKeys[i] = prover.getPublicKey();
			BanksSecretKeys[i] = prover.getSecretKey();
			ECPoint temp = G.multiply(BanksSecretKeys[i]);
			if (!temp.equals(prover.getPublicKey())) {
				System.out.println("Keys for " + i + " WRONG!!");
			}
		}
		params = new PedersenPublicParams(number, G, H, BanksPublicKeys);
		PedersenPublicFile paramsFile = new PedersenPublicFile(params);
		try {
			FileOutputStream fos = new FileOutputStream(filename);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(paramsFile);
			oos.close();
		} catch (IOException e) {
			System.out.println("Cannot write Pedersen Parameters to file");
			e.printStackTrace();
		}
		try {
			for (int i = 0; i < number; i++) {
				FileOutputStream fos = new FileOutputStream(keys + i + ".secret");
				BufferedOutputStream bos = new BufferedOutputStream(fos);
				ObjectOutputStream oos = new ObjectOutputStream(bos);
				oos.writeObject(BanksSecretKeys[i]);
				oos.close();
			}

		} catch (IOException e) {
			System.out.println("Cannot write Secret Keys to file");
			e.printStackTrace();
		}
	}

	public void init(int number, String filename, String keys) throws NoSuchAlgorithmException {
		BigInteger xCoord = new BigInteger("77da99d806abd13c9f15ece5398525119d11e11e9836b2ee7d23f6159ad87d4", 16);
		BigInteger yCoord = new BigInteger("a7094ec08a38b3befe52360b356573d2af2806a6eab38f2b323b428565ffe0e5", 16);
		ECPoint G = ecCurve.createPoint(xCoord, yCoord);
		xCoord = new BigInteger("f0da850a6b7c61a66cdd43ac7529affb1aaf2111a10a5e15dd8619fef0f5b754", 16);
		yCoord = new BigInteger("6c8a8967fbbb58983ed41b0672766f7017a4f01ee9dc27e3d3474179ae4817f1", 16);
		ECPoint H = ecCurve.createPoint(xCoord, yCoord);
		if (G.isValid() && H.isValid()) {
			System.out.println("G and H are valid");
		}
		ECPoint[] BanksPublicKeys = new ECPoint[number];
		BigInteger[] BanksSecretKeys = new BigInteger[number];

		for (int i = 0; i < number; i++) {
			SchnorrProver prover = new SchnorrProver(BigInteger.valueOf(i));
			BanksPublicKeys[i] = prover.getPublicKey();
			BanksSecretKeys[i] = prover.getSecretKey();
			//ECPoint temp = G.multiply(BanksSecretKeys[i]);
			ECPoint temp = H.multiply(BanksSecretKeys[i]);
			if (!temp.equals(prover.getPublicKey())) {
				System.out.println("Keys for " + i + " WRONG!!");
			}
		}
		params = new PedersenPublicParams(number, G, H, BanksPublicKeys);
		PedersenPublicFile paramsFile = new PedersenPublicFile(params);
		try {
			FileOutputStream fos = new FileOutputStream(filename);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(paramsFile);
			oos.close();
		} catch (IOException e) {
			System.out.println("Cannot write Pedersen Parameters to file");
			e.printStackTrace();
		}
		try {
			for (int i = 0; i < number; i++) {
				FileOutputStream fos = new FileOutputStream(keys + i + ".secret");
				BufferedOutputStream bos = new BufferedOutputStream(fos);
				ObjectOutputStream oos = new ObjectOutputStream(bos);
				oos.writeObject(BanksSecretKeys[i]);
				oos.close();
			}

		} catch (IOException e) {
			System.out.println("Cannot write Secret Keys to file");
			e.printStackTrace();
		}
	}

	public PedersenPublicParams readParamsFromFile(String filename) throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(filename);
		BufferedInputStream bis = new BufferedInputStream(fis);
		ObjectInputStream ois = new ObjectInputStream(bis);
		PedersenPublicFile paramsFile = (PedersenPublicFile) ois.readObject();
		params = paramsFile.getPedersenPublicParams();
		ois.close();
		return params;
	}

	public BigInteger readSecretFromFile(String keys, int user) throws IOException, ClassNotFoundException {
		FileInputStream fis = new FileInputStream(keys + user + ".secret");
		BufferedInputStream bis = new BufferedInputStream(fis);
		ObjectInputStream ois = new ObjectInputStream(bis);
		BigInteger secret = (BigInteger) ois.readObject();
		ois.close();
		return secret;
	}

	public PedersenPublicParams getParams() {
		return params;
	}

	public Pedersen pedersenCommit(BigInteger littleV) {
		// little R taken from Order
		BigInteger littleR = Common.Util.randomFromZn(P, new Random());
		ECPoint commit = pedersenCommitR(littleV, littleR, params.getG(), params.getH());
		Open openValue = new Open(littleV, littleR);
		return new Pedersen(commit, openValue);
	}

	public Pedersen pedersenCommit(BigInteger littleV, BigInteger littleR) {
		ECPoint commit = pedersenCommitR(littleV, littleR, params.getG(), params.getH());
		Open openValue = new Open(littleV, littleR);
		return new Pedersen(commit, openValue);
	}

	public ECPoint pedersenCommitR(BigInteger littleV, BigInteger littleR, ECPoint G, ECPoint H) {
		// (G^littleV)modP, (H^littleR)modP :: lhs, rhs (bigV::bigR)
		BigInteger modV = littleV;
		BigInteger modR = littleR;
		ECPoint lhs = G.multiply(modV);
		ECPoint rhs = H.multiply(modR);
		return lhs.add(rhs);
	}

	public boolean checkCommitment(PedersenPublicParams params, BigInteger littleV, BigInteger littleR,
			ECPoint pedComm) {
		ECPoint tempPedersen = pedersenCommitR(littleV, littleR, params.getG(), params.getH());
		return (tempPedersen.equals(pedComm));
	}

	public boolean checkCommitment(PedersenPublicParams params, Open open, ECPoint pcomm) {
		return checkCommitment(params, open.getValue(), open.getRandomness(), pcomm);
	}
}