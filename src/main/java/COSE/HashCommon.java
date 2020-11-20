package COSE;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public abstract class HashCommon extends Message {

	protected String contextString;
	protected byte[] rgbHash;

	byte[] computeHash(byte[] rgbToBeSigned) throws CoseException {
		AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
		return computeHash(alg, rgbToBeSigned);
	}

	protected byte[] computeHash(AlgorithmID alg, byte[] rgbToBeHashed) throws CoseException {
		String algName = null;

		switch (alg) {
		case SHA_512:
			algName = "SHA-512";
			break;
		case SHA_256:
			algName = "SHA-256";
			break;
		case SHA3_512:
			algName = "SHA3-512";
			break;
		case SHA3_256:
			algName = "SHA3-256";
			break;

        default:
			throw new CoseException("Unsupported Algorithm Specified");
		}

		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algName);
			rgbHash = messageDigest.digest(rgbToBeHashed);
			return rgbHash;
		} catch (NoSuchAlgorithmException e) {
			throw new CoseException("Hashing not possible. Unsupported Algorithm Specified");
		}

	}

	public byte[] getHashedContent() throws CoseException {
		if (rgbHash == null)
			throw new CoseException("No hashed Content Specified");

		return rgbHash;
	}

}
