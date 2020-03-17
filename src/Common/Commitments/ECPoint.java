package Common.Commitments;

import java.io.Serializable;
import java.math.BigInteger;

public class ECPoint implements Serializable {

	private static final long serialVersionUID = 8372645283516642704L;
	private final BigInteger xCoord;
	private final BigInteger yCoord;

	@SuppressWarnings("static-access")
	public ECPoint(BigInteger x, BigInteger y) {
		this.xCoord = x;
		this.yCoord = y;
	}

	public BigInteger getX() {
		return xCoord;
	}

	public BigInteger getY() {
		return yCoord;
	}

}
