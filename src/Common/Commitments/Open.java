package Common.Commitments;

import java.math.BigInteger;

public class Open {
	
	private final BigInteger value;
	private final BigInteger randomness;

	public Open(BigInteger value, BigInteger randomness) {
		this.value = value;
		this.randomness = randomness;
	}

	public BigInteger getValue() {
		return value;
	}
	
	public BigInteger getRandomness() {
		return randomness;
	}
}
