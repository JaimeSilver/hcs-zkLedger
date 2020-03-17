package net.aochain;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import com.hedera.hashgraph.sdk.HederaStatusException;
import com.hedera.hashgraph.sdk.TransactionReceipt;

import Common.Commitments.PedersenPublicParams;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofProver;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import net.aochain.hcs.ConsensusPubSubWithSubmitKey;

public class Transaction implements Serializable {
	private static int Participants;
	private PedersenPublicParams Parameters;
	private Pedersen[] Commitments = null;
	private BigInteger[] Randomness = null;
	private ECPoint[] AuditTokens = null;
	private ECPoint[] Token1P = null;
	private ECPoint[] Token2P = null;
	private ZK[] DZKP = null;
	private ECPoint commRP = null;
	private static final long serialVersionUID = 8372645283516642704L;
	private static BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
			16);
	private static BigInteger Q = new BigInteger(
			"205115282021455665897114700593932402728804164701536103180137503955397371");

	@SuppressWarnings("static-access")
	public Transaction(int participants, PedersenPublicParams p) {
		this.Participants = participants;
		this.Parameters = p;
		init(participants);
	}

	public String toString() {
		String result = "";
		for (int i = 0; i < Participants; i++) {
			result += Integer.toString(i);
			result += Commitments[i].getCommitment().toString();
			result += AuditTokens[i].toString();
		}
		return result;
	}

	public Pedersen[] getPedersen() {
		return this.Commitments;
	}

	public Pedersen getPedersen(int user) {
		return this.Commitments[user];
	}

	public ECPoint[] getAuditTokens() {
		return this.AuditTokens;
	}

	public ECPoint[] getToken1P() {
		return this.Token1P;
	}

	public ECPoint[] getToken2P() {
		return this.Token2P;
	}

	public ECPoint getAuditTokens(int user) {
		return this.AuditTokens[user];
	}

	public ZK[] getDZKP() {
		return this.DZKP;
	}

	public ECPoint getCOMMRP() {
		return this.commRP;
	}
	
	public ECPoint getToken1P(int user) {
		return this.Token1P[user];
	}

	public ECPoint getToken2P(int user) {
		return this.Token2P[user];
	}

	public ZK getDZKP(int user) {
		return this.DZKP[user];
	}

	public Transaction transfer(int payer, int receiver, BigInteger value) {
		if (payer == receiver) {
			System.out.println("Payer is the same as receiver");
			return null;
		}
		form_pedersen(payer, receiver, value);
		return this;
	}

	public Transaction deposit(int receiver, BigInteger value) {
		form_pedersen(-1, receiver, value);
		return this;
	}

	public Transaction withdraw(int payer, BigInteger value) {
		form_pedersen(payer, -1, value);
		return this;
	}

	public boolean isBalanced() {
		ECPoint commVALIDATE = null;
		BigInteger totalV = BigInteger.ZERO;
		BigInteger totalR = BigInteger.ZERO;
		for (int i = 0; i < Participants; i++) {
			totalR = totalR.add(this.Randomness[i]);
			totalV = totalV.add(this.Commitments[i].getOpen().getValue());
			if (commVALIDATE == null) {
				commVALIDATE = this.Commitments[i].getCommitment();
			} else {
				commVALIDATE = commVALIDATE.add(this.Commitments[i].getCommitment());
			}
		}
		commVALIDATE = commVALIDATE.normalize();
		ECPoint auxBASE = Parameters.getH().multiply(P);
		boolean response = commVALIDATE.equals(auxBASE);
		if (!response) {
			System.out.println("Transaction is not BALANCED");
			System.out.println("totalV " + totalV.mod(P));
			System.out.println("totalR " + totalR.mod(P));
			System.out.println("P*H        " + auxBASE);
			System.out.println("Summa Comm " + commVALIDATE);
		}
		return response;
	}

	public boolean isCorrect(int i, BigInteger SecretKey) {
		if (i > this.Participants) {
			System.out.println("Incorrect user");
			return false;
		}

		BigInteger value = Commitments[i].getOpen().getValue();
		ECPoint lsh = AuditTokens[i];

		BigInteger exp = SecretKey.multiply(Commitments[i].getOpen().getValue());
		lsh = lsh.add(Parameters.getG().multiply(exp));

		ECPoint rsh = Commitments[i].getCommitment().multiply(SecretKey);
		boolean response = lsh.equals(rsh);
		if (!response) {
			System.out.println("AuditTokens " + lsh);
			System.out.println("Other Side  " + rsh);
		}
		return response;
	}

	private void form_pedersen(int payer, int receiver, BigInteger value) {
		// Now work on the Pedersen commitments
		Pedersen PedersenFactory = new Pedersen();
		PedersenFactory.init(this.Parameters);
		ECPoint[] BankPKs = this.Parameters.getPublicKeys();
		BigInteger totalR = BigInteger.ZERO;
		for (int i = 0; i < Participants; i++) {
			// Build proof of balance by selecting randomness to match the total
			if (i == (Participants - 1)) {
				this.Randomness[i] = P.subtract(totalR);
				if (i == payer) {
					this.Commitments[i] = PedersenFactory.pedersenCommit(value.negate(), this.Randomness[i]);
				} else if (i == receiver) {
					this.Commitments[i] = PedersenFactory.pedersenCommit(value, this.Randomness[i]);
				} else {
					this.Commitments[i] = PedersenFactory.pedersenCommit(BigInteger.ZERO, this.Randomness[i]);
				}
			} else {
				if (i == payer) {
					this.Commitments[i] = PedersenFactory.pedersenCommit(value.negate());
				} else if (i == receiver) {
					this.Commitments[i] = PedersenFactory.pedersenCommit(value);
				} else {
					this.Commitments[i] = PedersenFactory.pedersenCommit(BigInteger.ZERO);
				}
				this.Randomness[i] = this.Commitments[i].getOpen().getRandomness();
				totalR = totalR.add(this.Randomness[i]);
			}
			// Define Tokens as PublicKeys^Random[i]. Keep PublicKeys as Schnorr's PKs.
			this.AuditTokens[i] = BankPKs[i].multiply(this.Commitments[i].getOpen().getRandomness());
		}
	}

	private void init(int participants) {
		this.Commitments = new Pedersen[participants];
		this.Randomness = new BigInteger[participants];
		this.AuditTokens = new ECPoint[participants];
		this.Token1P = new ECPoint[participants];
		this.Token2P = new ECPoint[participants];
		this.DZKP = new ZK[participants];
	}

	public void buildConsistency(BigInteger rPR, int payer, BigInteger currentNet, ECPoint[] t, ECPoint[] s,
			BigInteger[] sk, ECPoint[] pk) throws NoSuchAlgorithmException {
		// Now work on the Pedersen commitments
		Pedersen PedersenFactory = new Pedersen();
		PedersenFactory.init(this.Parameters);
		ECPoint[] BankPKs = this.Parameters.getPublicKeys();

		this.commRP = PedersenFactory.pedersenCommit(rPR, currentNet).getCommitment();
		ECPoint lhs = null;
		ECPoint rhs = null;
		BigInteger skPayer = null;
		if (payer < 0) {
			skPayer = Q;
		} else {
			skPayer = sk[payer];
		}

		for (int i = 0; i < Participants; i++) {
			// Build proof of balance by selecting randomness to match the total
			if (i == payer) {
				this.Token1P[i] = BankPKs[i].multiply(rPR);
				this.Token2P[i] = AuditTokens[i].add(commRP.subtract(s[i])).multiply(skPayer);
			} else {
				this.Token1P[i] = t[i].add((commRP.subtract(s[i])).multiply(skPayer));
				this.Token2P[i] = BankPKs[i].multiply(rPR);
			}
			this.Token1P[i] = this.Token1P[i].normalize();
			this.Token2P[i] = this.Token2P[i].normalize();
			
			//Calculate DZKP 1 and 2
			ECPoint g1 = s[i].subtract(commRP);
			ECPoint y1 = t[i].subtract(this.Token1P[i]);
			ECPoint g2 = pk[i];
			ECPoint y2 = AuditTokens[i].subtract(this.Token2P[i]);
			this.DZKP[i] = new ZK(g1,g2,y1,y2, this.Token1P[i], this.Token2P[i], skPayer, this.Randomness[i].subtract(rPR));						
			// Test the DZKP 1
			ECPoint lhsG1 = g1.multiply(this.DZKP[i].resp1);
			ECPoint rhsG1 = (this.DZKP[i].g1x.multiply(this.DZKP[i].chall1)).add(this.DZKP[i].g1w);
			boolean outputG1 = lhsG1.equals(rhsG1);
			if (!outputG1) {
				System.out.println("outputG1 FAILED... ");
				break;
			}
			ECPoint lhsY1 = y1.multiply(this.DZKP[i].resp1);
			ECPoint rhsY1 = (this.DZKP[i].y1x.multiply(this.DZKP[i].chall1)).add(this.DZKP[i].y1w);
			boolean outputY1 = lhsY1.equals(rhsY1);
			if (!outputY1) {
				System.out.println("outputY1 FAILED... ");
				break;
			}

		}
	}

	public TransactionReceipt broadcast(ConsensusPubSubWithSubmitKey hcs) {
		TransactionReceipt msgReceipt = null;
		try {
			msgReceipt = hcs.execute(this.toString(), false)[0];
			return msgReceipt;
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		} catch (HederaStatusException e1) {
			e1.printStackTrace();
		}
		return null;
	}

	public ECPoint[] addPedersen(ECPoint[] cachePedersen) {
		ECPoint[] respuesta = new ECPoint[Participants];
		for (int i = 0; i < Participants; i++) {
			respuesta[i] = this.getPedersen(i).getCommitment();
			if (cachePedersen != null) {
				respuesta[i] = respuesta[i].add(cachePedersen[i]);
			}
		}
		return respuesta;
	}

	public ECPoint[] addAuditTokens(ECPoint[] cacheAudit) {
		ECPoint[] respuesta = new ECPoint[Participants];
		for (int i = 0; i < Participants; i++) {
			respuesta[i] = this.getAuditTokens(i);
			if (cacheAudit != null) {
				respuesta[i] = respuesta[i].add(cacheAudit[i]);
			}
		}
		return respuesta;
	}

	public RangeProof buildProofAssets(GeneratorParams bulletParameters, int payer, BigInteger currentNet,
			BigInteger randomness) {
		// Testing Range Proofs for Proof of Assets
		GroupElement v = bulletParameters.getBase().commit(currentNet, randomness);
		PeddersenCommitment<?> witness = new PeddersenCommitment<>(bulletParameters.getBase(), currentNet, randomness);
		BouncyCastleECPoint.addCount = 0;
		BouncyCastleECPoint.expCount = 0;
		RangeProof proof = new RangeProofProver().generateProof(bulletParameters, v, witness);
		return proof;
	}

	public BigInteger[] addBalance(BigInteger[] cacheBalance) {
		BigInteger[] respuesta = new BigInteger[Participants];
		for (int i = 0; i < Participants; i++) {
			respuesta[i] = this.getPedersen(i).getOpen().getValue();
			if (cacheBalance != null) {
				respuesta[i] = respuesta[i].add(cacheBalance[i]);
			}
		}
		return respuesta;
	}

	public boolean verifyDZKP(ECPoint commRP, ECPoint[] t, ECPoint[] s, ECPoint[] pk) {
		for (int i = 0; i < Participants; i++) {
			//Calculate G, Y for the two ZK1 and ZK2
			ECPoint g1 = s[i].subtract(commRP);
			ECPoint y1 = t[i].subtract(this.Token1P[i]);
			ECPoint g2 = pk[i];
			ECPoint y2 = AuditTokens[i].subtract(this.Token2P[i]);

			// Test the DZKP 1
			ECPoint lhsG1 = g1.multiply(this.DZKP[i].resp1);
			ECPoint rhsG1 = (this.DZKP[i].g1x.multiply(this.DZKP[i].chall1)).add(this.DZKP[i].g1w);
			boolean outputG1 = lhsG1.equals(rhsG1);
			if (!outputG1) {
				System.out.println("outputG1 FAILED... ");
				return false;
			}
			ECPoint lhsY1 = y1.multiply(this.DZKP[i].resp1);
			ECPoint rhsY1 = (this.DZKP[i].y1x.multiply(this.DZKP[i].chall1)).add(this.DZKP[i].y1w);
			boolean outputY1 = lhsY1.equals(rhsY1);
			if (!outputY1) {
				System.out.println("outputY1 FAILED... ");
				return false;
			}

			// Test the DZKP 2
			ECPoint lhsG2 = g2.multiply(this.DZKP[i].resp2);
			ECPoint rhsG2 = (this.DZKP[i].g2x.multiply(this.DZKP[i].chall2)).add(this.DZKP[i].g2w);
			boolean outputG2 = lhsG2.equals(rhsG2);
			if (!outputG2) {
				System.out.println("outputG2 FAILED... ");
				return false;
			}
			ECPoint lhsY2 = y2.multiply(this.DZKP[i].resp2);
			ECPoint rhsY2 = (this.DZKP[i].y2x.multiply(this.DZKP[i].chall2)).add(this.DZKP[i].y2w);
			boolean outputY2 = lhsY2.equals(rhsY2);
			if (!outputY2) {
				System.out.println("outputY2 FAILED... ");
				return false;
			}
		}
		return true;
	}
}