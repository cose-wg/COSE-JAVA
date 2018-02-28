/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.*;
import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;

/**
 *
 * @author jimsch
 */
public class ECPublicKey implements java.security.interfaces.ECPublicKey {
    ECPoint point;
    String algorithm;
    ECParameterSpec ecParameterSpec;
    byte[] spkiEncoded;
            
    public ECPublicKey(OneKey oneKey) throws CoseException, IOException
    {
        X9ECParameters p = oneKey.GetCurve();
        byte[] rgbKey;
        byte[] X = oneKey.get(KeyKeys.EC2_X).GetByteString();
        
        if (oneKey.get(KeyKeys.EC2_Y).getType()== CBORType.Boolean) {
            rgbKey = new byte[X.length + 1];
            System.arraycopy(X, 0, rgbKey, 1, X.length);
            rgbKey[0] = (byte) (2 + (oneKey.get(KeyKeys.EC2_Y).AsBoolean() ? 1 : 0));
            org.bouncycastle.math.ec.ECPoint pubPoint;
            pubPoint = p.getCurve().decodePoint(rgbKey);
            point = new ECPoint(pubPoint.getAffineXCoord().toBigInteger(), pubPoint.getAffineYCoord().toBigInteger());
        }
        else {
            rgbKey = new byte[X.length*2+1];
            System.arraycopy(X, 0,rgbKey, 1, X.length);
            byte[] Y = oneKey.get(KeyKeys.EC2_Y).GetByteString();
            System.arraycopy(Y, 0, rgbKey, 1+X.length, X.length);
            rgbKey[0] = 4;
            point = new ECPoint(new BigInteger(1, X), new BigInteger(1, oneKey.get(KeyKeys.EC2_Y).GetByteString()));
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
        
        CBORObject curve = oneKey.get(KeyKeys.EC2_Curve);
        ASN1ObjectIdentifier curveOID;
        if (curve.equals(KeyKeys.EC2_P256)) {
            curveOID = org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1;
        }
        else if (curve.equals(KeyKeys.EC2_P384)) {
        curveOID = org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1;
        }
        else if (curve.equals(KeyKeys.EC2_P521)) {
            curveOID =org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp521r1;
        }
        else {
            throw new CoseException("Unrecognized Curve");
        }
        
        ECField field = new ECFieldFp(p.getCurve().getField().getCharacteristic());
        EllipticCurve crv = new EllipticCurve(field, p.getCurve().getA().toBigInteger(), p.getCurve().getB().toBigInteger());
        ECPoint pt = new ECPoint(p.getG().getRawXCoord().toBigInteger(), p.getG().getRawYCoord().toBigInteger());
        ecParameterSpec = new ECParameterSpec(crv, pt, p.getN(), p.getH().intValue());
        
        
        AlgorithmIdentifier alg =  new AlgorithmIdentifier(org.bouncycastle.asn1.x9.X9Curve.id_ecPublicKey,  curveOID);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(alg, rgbKey);
        spkiEncoded = spki.getEncoded();
        
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
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        return spkiEncoded;
    }

    @Override
    public ECParameterSpec getParams() {
        return ecParameterSpec;
    }
    
}
