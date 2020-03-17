package Common.Commitments;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

public class PedersenPublicFile implements Serializable {
	private static final long serialVersionUID = 8372645283516642704L;
	private int Total_participants;
	protected String ECName = "secp256k1";
	protected ECPoint G;
	protected ECPoint H;
	private ECPoint[] BanksPublicKeys;

	public PedersenPublicFile(int Total_participants, ECPoint g, ECPoint h, ECPoint[] BankPublicKeys) {
		this.Total_participants = Total_participants;
		this.G = g;
		this.H = h;
		this.BanksPublicKeys = BankPublicKeys;
	}
	public PedersenPublicFile(PedersenPublicParams params) {
		this.Total_participants = params.getTotalParticipants();
		this.G = new ECPoint(params.G.getXCoord().toBigInteger(),params.G.getYCoord().toBigInteger());
		this.H = new ECPoint(params.H.getXCoord().toBigInteger(),params.H.getYCoord().toBigInteger());
		this.BanksPublicKeys = new ECPoint[Total_participants];
		for (int i = 0; i<Total_participants; i++) {
			BigInteger auxX = params.getBanksPublicKeys(i).getXCoord().toBigInteger();
			BigInteger auxY = params.getBanksPublicKeys(i).getYCoord().toBigInteger();
			this.BanksPublicKeys[i] = new ECPoint(auxX,auxY);	
		}
		
	}
	public PedersenPublicParams getPedersenPublicParams() {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(this.ECName);
		SecP256K1Curve ecCurve = (SecP256K1Curve) ecSpec.getCurve();		
		org.bouncycastle.math.ec.ECPoint _G = ecCurve.createPoint(this.G.getX(), this.G.getY());
		org.bouncycastle.math.ec.ECPoint _H = ecCurve.createPoint(this.H.getX(), this.H.getY());
		org.bouncycastle.math.ec.ECPoint[] _BanksPublicKeys = new org.bouncycastle.math.ec.ECPoint[Total_participants];
		for (int i = 0; i<Total_participants; i++) {
			BigInteger auxX = this.BanksPublicKeys[i].getX();
			BigInteger auxY = this.BanksPublicKeys[i].getY();
			_BanksPublicKeys[i] = ecCurve.createPoint(auxX,auxY);	
		}		
		PedersenPublicParams params = new PedersenPublicParams(Total_participants, _G, _H, _BanksPublicKeys);
		return params;
	}	
}
