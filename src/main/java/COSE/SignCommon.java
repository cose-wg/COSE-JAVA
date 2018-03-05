/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import static java.lang.Integer.min;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author jimsch
 */

public abstract class SignCommon extends Message {
    protected String contextString;

    byte[] computeSignature(byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        String      algName = null;
        int         sigLen = 0;
        
        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                sigLen = 32;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                sigLen = 48;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                sigLen = 66;
                break;
                
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        if (cnKey == null) {
            throw new NullPointerException();
        }
        
        PrivateKey  privKey = null;
        try {
            privKey = cnKey.AsPrivateKey();
        } catch (NullPointerException ex) {
            throw new CoseException("Private key required to sign");
        }
        
        byte[]      result = null;
        try {
            Signature sig = Signature.getInstance(algName);
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            result = sig.sign();
            result = convertDerToConcat(result, sigLen);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }
        
        return result;
    }
    
    private byte[] convertDerToConcat(byte[] der, int len) throws CoseException {
        // this is far too naive
        byte[] concat = new byte[len * 2];

        // assumes BITSTRING is organized as "R + S"
        int kLen = 4;
        if (der[0] != 0x30) {
            throw new CoseException("Unexpected signature input");
        }
        if ((der[1] & 0x80) != 0) {
            // offset actually 4 + (7-bits of byte 1)
            kLen = 4 + (der[1] & 0x7f);
        }
        
        // calculate start/end of R
        int rOff = kLen;
        int rLen = der[rOff - 1];
        int rPad = 0;
        if (rLen > len) {
            rOff += (rLen - len);
            rLen = len;
        } else {
            rPad = (len - rLen);
        }
        // copy R
        System.arraycopy(der, rOff, concat, rPad, rLen);
        
        // calculate start/end of S
        int sOff = rOff + rLen + 2;
        int sLen = der[sOff - 1];
        int sPad = 0;
        if (sLen > len) {
            sOff += (sLen - len);
            sLen = len;
        } else {
            sPad = (len - sLen);
        }
        // copy S
        System.arraycopy(der, sOff, concat, len + sPad, sLen);
        
        return concat;
    }
    
    boolean validateSignature(byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        Digest digest;
        
        switch (alg) {
            case ECDSA_256:
                digest = new SHA256Digest();
                break;
            
            case ECDSA_384:
                digest = new SHA384Digest();
                break;
                
            case ECDSA_512:
                digest = new SHA512Digest();
                break;
            
            default:
                throw new CoseException("Unsupported algorithm specified");
        }
        
        switch (alg) {
            case ECDSA_256:
            case ECDSA_384:
            case ECDSA_512:
            {
                byte[] rgbR = new byte[rgbSignature.length/2];
                byte[] rgbS = new byte[rgbSignature.length/2];
                System.arraycopy(rgbSignature, 0, rgbR, 0, rgbR.length);
                System.arraycopy(rgbSignature, rgbR.length, rgbS, 0, rgbR.length);
                
                digest.update(rgbToBeSigned, 0, rgbToBeSigned.length);
                byte[] rgbDigest = new byte[digest.getDigestSize()];
                digest.doFinal(rgbDigest, 0);
                
                X9ECParameters p = cnKey.GetCurve();
                ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
                BigInteger bnX = new BigInteger(1, cnKey.get(KeyKeys.EC2_X).GetByteString());
                ECPoint point = p.getCurve().createPoint(bnX, new BigInteger(1, cnKey.get(KeyKeys.EC2_Y).GetByteString()));
                
                ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, parameters);
                
                ECDSASigner ecdsa = new ECDSASigner();
                ecdsa.init(false, pubKey);
                return ecdsa.verifySignature(rgbDigest, new BigInteger(1, rgbR), new BigInteger(1, rgbS));                
            }
            
            default:
                throw new CoseException("Internal error");
        }
    }
}
