/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.*;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import org.bouncycastle.asn1.x9.X9ECParameters;

/**
 *
 * @author jimsch
 */
public class ECPublicKey implements java.security.interfaces.ECPublicKey {
    ECPoint point;
    String algorithm;
    ECParameterSpec ecParameterSpec;
            
    public ECPublicKey(OneKey oneKey) throws CoseException
    {
        X9ECParameters p = oneKey.GetCurve();
        
        if (oneKey.get(KeyKeys.EC2_Y).getType()== CBORType.Boolean) {
            byte[] X = oneKey.get(KeyKeys.EC2_X.AsCBOR()).GetByteString();
            byte[] rgb = new byte[X.length + 1];
            System.arraycopy(X, 0, rgb, 1, X.length);
            rgb[0] = (byte) (2 + (oneKey.get(KeyKeys.EC2_Y).AsBoolean() ? 1 : 0));
            org.bouncycastle.math.ec.ECPoint pubPoint;
            pubPoint = p.getCurve().decodePoint(rgb);
            point = new ECPoint(point.getAffineX(), point.getAffineY());
        }
        else {
            point = new ECPoint(new BigInteger(1, oneKey.get(KeyKeys.EC2_X).GetByteString()), new BigInteger(1, oneKey.get(KeyKeys.EC2_Y).GetByteString()));
        }

        /*
        switch (AlgorithmID.FromCBOR(oneKey.get(KeyKeys.Algorithm))) {
            case ECDH_ES_HKDF_256:
            case ECDH_ES_HKDF_512:
            case ECDH_SS_HKDF_256:
            case ECDH_SS_HKDF_512:
            case ECDH_ES_HKDF_256_AES_KW_128:
            case ECDH_ES_HKDF_256_AES_KW_192:
            case ECDH_ES_HKDF_256_AES_KW_256:
            case ECDH_SS_HKDF_256_AES_KW_128:
            case ECDH_SS_HKDF_256_AES_KW_192:
            case ECDH_SS_HKDF_256_AES_KW_256:
                algorithm = "ECDH";
                break;
                
            case ECDSA_256:
                algorithm = "SHA256withECDSA";
                break;
                
            case ECDSA_384:
                algorithm = "SHA384withECDSA";
                break;
                
            case ECDSA_512:
                algorithm = "SHA512withECDSA";
                break;
                
            default:
                throw new CoseException("No algorithm specified");
        }
        */
        algorithm = "EC"; // This seems wrong to me asit returns the KeyFactory name and 
                          // there is no distinction between ECDH and ECDSA while there
                          // is for DSA vs DiffieHellman.
        
        ECField field = new ECFieldFp(p.getCurve().getField().getCharacteristic());
        EllipticCurve crv = new EllipticCurve(field, p.getCurve().getA().toBigInteger(), p.getCurve().getB().toBigInteger());
        ECPoint pt = new ECPoint(p.getG().getRawXCoord().toBigInteger(), p.getG().getRawYCoord().toBigInteger());
        ecParameterSpec = new ECParameterSpec(crv, pt, p.getN(), p.getH().intValue());
    }
    
    @Override
    public ECPoint getW() {
        return point;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public ECParameterSpec getParams() {
        return ecParameterSpec;
    }
    
}
