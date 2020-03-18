import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

import com.hedera.hashgraph.sdk.HederaStatusException;
import com.hedera.hashgraph.sdk.TransactionReceipt;

import Common.Commitments.PedersenPublicParams;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.algebra.Secp256k1;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofVerifier;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import net.aochain.Pedersen;
import net.aochain.SchnorrProver;
import net.aochain.SchnorrVerifier;
import net.aochain.Transaction;
import net.aochain.hcs.ConsensusPubSubWithSubmitKey;

public final class exampleTrader {

	private exampleTrader() {
	}

	private static int Total_participants;
	private static BigInteger[] BanksSecretKeys = null;

	private static PedersenPublicParams parameters;
	private static BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			16);
	private static BigInteger Q = new BigInteger(
			"205115282021455665897114700593932402728804164701536103180137503955397371");
	public static Secp256k1 curve = new Secp256k1();

	public static void main(String[] args) throws NoSuchAlgorithmException, ClassNotFoundException, IOException {

		// Lets make sure Schnorr Works
		SchnorrProver prover = new SchnorrProver(BigInteger.valueOf(0));
		System.out.println("Schnorr Prover: " + prover);

		if (SchnorrVerifier.verify(prover.getGenPoint(), prover.getPublicKey(), prover.getV(), prover.getR(),
				BigInteger.valueOf(0))) {
			System.out.println("Schnorr Verifier: works");
			System.out.println();
		} else {
			System.out.println("Schnorr Verifier: failed");
			System.out.println();

			return;
		}

		// Now work on the Pedersen commitments
		Pedersen PedersenFactory = new Pedersen();
		// Set Overall Parameters
		GeneratorParams bulletParameters = GeneratorParams.generateParams(256, curve);

		// Define N banks for test
		PedersenFactory.init(4, "./resources/Pedersen.env", "./resources/SecretKeys");
		parameters = PedersenFactory.getParams();
		Total_participants = parameters.getTotalParticipants();
		BanksSecretKeys = new BigInteger[Total_participants];

		System.out.println("G: " + PedersenFactory.getParams().getG());
		System.out.println("G: " + bulletParameters.getBase().g.stringRepresentation());
		System.out.println("H: " + PedersenFactory.getParams().getH());
		System.out.println("H: " + bulletParameters.getBase().h.stringRepresentation());

		// Generate a very simple test to validate EC operations
		ECPoint temp1 = parameters.getH().multiply(BigInteger.valueOf(10));
		ECPoint temp3 = parameters.getH().multiply(BigInteger.valueOf(2));
		temp1 = temp1.add(temp3);
		ECPoint temp2 = parameters.getH().multiply(BigInteger.valueOf(12));
		if (temp1.equals(temp2)) {
			System.out.println("Elliptic Curve Operations Work");
		} else {
			System.out.println("Elliptic Curve Operations Failed");
			System.out.println("Temp1 " + temp1);
			System.out.println("Temp2 " + temp2);
			return;
		}

		ECPoint temp4 = parameters.getH().multiply(P.add(BigInteger.ONE));
		ECPoint temp5 = parameters.getH().multiply(P.negate());
		temp4 = temp4.add(temp5);
		if (temp4.equals(parameters.getH())) {
			System.out.println("Elliptic Curve Operations Inverse Work");
		} else {
			System.out.println("Elliptic Curve Operations Failed");
		}

		// Load Secret Keys
		for (int i = 0; i < Total_participants; i++) {
			BanksSecretKeys[i] = PedersenFactory.readSecretFromFile("./resources/SecretKeys", i);
		}

		// Confirm G != H
		if (!parameters.getG().equals(parameters.getH())) {
			System.out.println("G is not equal H");
			System.out.println();
		}

		// Confirm that the retrieve works
		PedersenPublicParams parameters2 = PedersenFactory.readParamsFromFile("./resources/Pedersen.env");
		if (!parameters.equals(parameters2)) {
			System.out.println("Error retrieving PublicKeys File");
		} else {
			System.out.println("PublicKeys File retrieved");
			System.out.println();
		}

		// Create Consensus Topic
		ConsensusPubSubWithSubmitKey hcs = new ConsensusPubSubWithSubmitKey(1);
		try {
			hcs.topic();
			System.out.println("************************************");
			System.out.println("Topic Generated" + hcs.getTopicId());
			System.out.println();
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (HederaStatusException e1) {
			e1.printStackTrace();
		}

		ECPoint[] cacheAudit = null;
		ECPoint[] cachePedersen = null;
		BigInteger[] cacheBalance = null;

		System.out.println("************************************");
		System.out.println("Generate transaction Zero");
		System.out.println();

		BigInteger number = BigInteger.valueOf(1500);

		Transaction trans0 = new Transaction(Total_participants, parameters);
		trans0.deposit(0, number);
		trans0.broadcast(hcs);
		cacheAudit = trans0.addAuditTokens(cacheAudit);
		cachePedersen = trans0.addPedersen(cachePedersen);
		cacheBalance = trans0.addBalance(cacheBalance);

		// Start of Proof of Assets
		BigInteger rPR = ProofUtils.randomNumber();
		BigInteger currentNet = cacheBalance[0];
		RangeProof proof = trans0.buildProofAssets(bulletParameters, -1, currentNet, rPR);
		GroupElement commRP = bulletParameters.getBase().commit(currentNet, rPR);

		System.out.println("************************************");
		System.out.println("Building Proof of Assets  TRANS 0");
		System.out.println("Comm of Range Proof          " + commRP.stringRepresentation());
		System.out.println("Total Bytes needed for Proof " + proof.serialize().length);
		System.out.println("Proof " + proof);
		System.out.println();

		// Verify Proof works
		try {
			GroupElement v = bulletParameters.getBase().commit(currentNet, rPR);
			RangeProof proof2 = new RangeProof(proof.getaI(), proof.getS(), proof.gettCommits(), proof.getTauX(),
					proof.getMu(), proof.getT(), proof.getProductProof());
			RangeProofVerifier verifier = new RangeProofVerifier();
			verifier.verify(bulletParameters, v, proof2);
		} catch (VerificationFailedException e) {
			System.out.println("Error in verification");
			return;
		}

		System.out.println("************************************");
		System.out.println("Sending Proof of Assets of Transaction ZERO");
		System.out.println();

		try {
			TransactionReceipt msgReceipt0 = null;
			TransactionReceipt msgReceipt1 = null;
			msgReceipt0 = hcs.execute(proof.serialize(), false)[0];
			msgReceipt1 = hcs.execute(commRP.stringRepresentation(), false)[0];
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (HederaStatusException e1) {
			e1.printStackTrace();
		}

		// Calculate Proof of Consistency Token1P and Token2P
		currentNet = cacheBalance[0];
		trans0.buildConsistency(rPR, -1, currentNet, cachePedersen, cacheAudit, BanksSecretKeys,
				parameters.getBanksPublicKeys());
		if (!trans0.verifyDZKP(trans0.getCOMMRP(), cachePedersen, cacheAudit, parameters.getBanksPublicKeys())) {
			System.out.println("Transaction 0 failed the DZKP");
			return;
		}

		// Test: Proof of correctness (This assumes all participants check their Keys)
		// AuditToken[m]*h^(SecretKey[i]*value[i]) ?= (PedersenComm[i])^SecretKey[i]
		for (int i = 0; i < Total_participants; i++) {
			if (!trans0.isCorrect(i, BanksSecretKeys[i])) {
				System.out.println("User " + i + " is NOT correctly formed");
				return;
			}
		}

		System.out.println("************************************");
		System.out.println("Generate transaction ONE");
		System.out.println();

		Transaction trans1 = new Transaction(Total_participants, parameters);
		trans1.transfer(0, 1, number);
		// A transaction is balanced if all R are equal to Zero.
		if (trans1.isBalanced()) {
			System.out.println("Transaction is Balanced");
		} else {
			return;
		}
		trans1.broadcast(hcs);
		cacheAudit = trans1.addAuditTokens(cacheAudit);
		cachePedersen = trans1.addPedersen(cachePedersen);
		cacheBalance = trans1.addBalance(cacheBalance);

		rPR = ProofUtils.randomNumber();
		currentNet = cacheBalance[0];
		proof = trans1.buildProofAssets(bulletParameters, 0, currentNet, rPR);
		commRP = bulletParameters.getBase().commit(currentNet, rPR);

		System.out.println("************************************");
		System.out.println("Building Proof of Assets  TRANS 1");
		System.out.println("Comm of Range Proof          " + commRP.stringRepresentation());
		System.out.println("Total Bytes needed for Proof " + proof.serialize().length);
		System.out.println("Proof " + proof);
		System.out.println();

		// Verify Proof works
		try {
			GroupElement v = bulletParameters.getBase().commit(currentNet, rPR);
			RangeProof proof2 = new RangeProof(proof.getaI(), proof.getS(), proof.gettCommits(), proof.getTauX(),
					proof.getMu(), proof.getT(), proof.getProductProof());
			RangeProofVerifier verifier = new RangeProofVerifier();
			verifier.verify(bulletParameters, v, proof2);
		} catch (VerificationFailedException e) {
			System.out.println("Error in verification");
			return;
		}

		System.out.println("************************************");
		System.out.println("Sending Proof of Assets of Transaction ONE");
		System.out.println();

		try {
			TransactionReceipt msgReceipt0 = null;
			TransactionReceipt msgReceipt1 = null;
			msgReceipt0 = hcs.execute(proof.serialize(), false)[0];
			msgReceipt1 = hcs.execute(commRP.stringRepresentation(), false)[0];
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (HederaStatusException e1) {
			e1.printStackTrace();
		}

		// Calculate Proof of Consistency Token1P and Token2P
		trans1.buildConsistency(rPR, 0, currentNet, cachePedersen, cacheAudit, BanksSecretKeys,
				parameters.getBanksPublicKeys());
		if (!trans1.verifyDZKP(trans1.getCOMMRP(), cachePedersen, cacheAudit, parameters.getBanksPublicKeys())) {
			System.out.println("Transaction 1 failed the DZKP");
			return;
		}

		// Proof of correctness (This assumes all participants check their Keys)
		// AuditToken[m]*h^(SecretKey[i]*value[i]) ?= (PedersenComm[i])^SecretKey[i]
		for (int i = 0; i < Total_participants; i++) {
			if (trans1.isCorrect(i, BanksSecretKeys[i])) {
				System.out.println("User " + i + " is correctly formed");
			}
		}

		System.out.println("************************************");
		System.out.println("Generate transaction TWO");
		System.out.println();
		Transaction trans2 = new Transaction(Total_participants, parameters);
		trans2.withdraw(1, number);
		trans2.broadcast(hcs);
		cacheAudit = trans2.addAuditTokens(cacheAudit);
		cachePedersen = trans2.addPedersen(cachePedersen);
		cacheBalance = trans2.addBalance(cacheBalance);

		rPR = ProofUtils.randomNumber();
		currentNet = cacheBalance[1];
		proof = trans1.buildProofAssets(bulletParameters, 1, currentNet, rPR);
		commRP = bulletParameters.getBase().commit(currentNet, rPR);

		System.out.println("************************************");
		System.out.println("Building Proof of Assets  TRANS 2");
		System.out.println("Comm of Range Proof          " + commRP.stringRepresentation());
		System.out.println("Total Bytes needed for Proof " + proof.serialize().length);
		System.out.println("Proof " + proof);
		System.out.println();

		// Verify Proof works
		try {
			GroupElement v = bulletParameters.getBase().commit(currentNet, rPR);
			RangeProof proof2 = new RangeProof(proof.getaI(), proof.getS(), proof.gettCommits(), proof.getTauX(),
					proof.getMu(), proof.getT(), proof.getProductProof());
			RangeProofVerifier verifier = new RangeProofVerifier();
			verifier.verify(bulletParameters, v, proof2);
		} catch (VerificationFailedException e) {
			System.out.println("Error in verification");
			return;
		}

		System.out.println("************************************");
		System.out.println("Sending Proof of Assets of Transaction TWO");
		System.out.println();

		try {
			TransactionReceipt msgReceipt0 = null;
			TransactionReceipt msgReceipt1 = null;
			msgReceipt0 = hcs.execute(proof.serialize(), false)[0];
			msgReceipt1 = hcs.execute(commRP.stringRepresentation(), false)[0];
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (HederaStatusException e1) {
			e1.printStackTrace();
		}

		// Calculate Proof of Consistency Token1P and Token2P
		currentNet = cacheBalance[1];
		trans2.buildConsistency(rPR, 1, currentNet, cachePedersen, cacheAudit, BanksSecretKeys,
				parameters.getBanksPublicKeys());

		// Proof of correctness (This assumes all participants check their Keys)
		// AuditToken[m]*h^(SecretKey[i]*value[i]) ?= (PedersenComm[i])^SecretKey[i]
		for (int i = 0; i < Total_participants; i++) {
			if (trans2.isCorrect(i, BanksSecretKeys[i])) {
				System.out.println("User " + i + " is correctly formed");
			}
		}

		// Clean the HCS backlog
		while (hcs.GetMessageQueue() != 0) {
			try {
				System.out.println("**********************************************");
				System.out.println("HCS missing messages: " + hcs.GetMessageQueue());
				System.out.println("Sleep: 1 second and Retry");
				Thread.sleep(1000);
			} catch (InterruptedException e) { // TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}
}
