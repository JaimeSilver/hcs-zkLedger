package Common.Commitments;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class PedersenPublicParams {

	private int Total_participants;
	protected ECCurve curve;
	protected ECPoint G;
	protected ECPoint H;

	private ECPoint[] BanksPublicKeys;

	public PedersenPublicParams(int Total_participants, ECPoint g, ECPoint h, ECPoint[] BankPublicKeys) {
		this.curve = g.getCurve();
		this.Total_participants = Total_participants;
		this.G = g;
		this.H = h;
		this.BanksPublicKeys = BankPublicKeys;
	}

	public int getTotalParticipants() {
		return Total_participants;
	}

	public ECCurve getCurve() {
		return curve;
	}

	public ECPoint getG() {
		return this.G;
	}

	public ECPoint getH() {
		return this.H;
	}

	public ECPoint[] getBanksPublicKeys() {
		return BanksPublicKeys;
	}

	public ECPoint[] getPublicKeys() {
		return BanksPublicKeys;
	}

	public ECPoint getBanksPublicKeys(int i) {
		return this.BanksPublicKeys[i];
	}

	public boolean equals(PedersenPublicParams that) {
		if (this.Total_participants == that.Total_participants && this.G.getXCoord().equals(that.getG().getXCoord())
				&& this.G.getYCoord().equals(that.getG().getYCoord())
				&& this.H.getXCoord().equals(that.getH().getXCoord())
				&& this.H.getYCoord().equals(that.getH().getYCoord())) {
			for (int i = 0; i < Total_participants; i++) {
				if (!BanksPublicKeys[i].getXCoord().equals(that.BanksPublicKeys[i].getXCoord())) {
					return false;
				}
				if (!BanksPublicKeys[i].getYCoord().equals(that.BanksPublicKeys[i].getYCoord())) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

}
