/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author jimsch
 */
public class COSE_ECPrivateKey implements java.security.interfaces.ECPrivateKey {
    ECPoint point;
    String algorithm;
    ECParameterSpec ecParameterSpec;
    BigInteger privateKey;
    byte[] encodedKey;
            
    public COSE_ECPrivateKey(OneKey oneKey) throws CoseException, IOException
    {
        X9ECParameters p = oneKey.GetCurve();
        
        privateKey = new BigInteger(1, oneKey.get(KeyKeys.EC2_D).GetByteString());

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
        algorithm = "EC";
        
        CBORObject curve = oneKey.get(KeyKeys.EC2_Curve);
        int keySize;
        ASN1ObjectIdentifier curveOID;
        if (curve.equals(KeyKeys.EC2_P256)) {
            curveOID = org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1;
            keySize = 256;
        }
        else if (curve.equals(KeyKeys.EC2_P384)) {
            curveOID = org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1;
            keySize= 384;
        }
        else if (curve.equals(KeyKeys.EC2_P521)) {
            curveOID =org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp521r1;
            keySize= 521;
        }
        else {
            throw new CoseException("Unrecognized Curve");
        }

        
        ECField field = new ECFieldFp(p.getCurve().getField().getCharacteristic());
        EllipticCurve crv = new EllipticCurve(field, p.getCurve().getA().toBigInteger(), p.getCurve().getB().toBigInteger());
        ECPoint pt = new ECPoint(p.getG().getRawXCoord().toBigInteger(), p.getG().getRawYCoord().toBigInteger());
        ecParameterSpec = new ECParameterSpec(crv, pt, p.getN(), p.getH().intValue());
        
        
        AlgorithmIdentifier alg =  new AlgorithmIdentifier(org.bouncycastle.asn1.x9.X9Curve.id_ecPublicKey,  curveOID);
        
        org.bouncycastle.asn1.sec.ECPrivateKey asnPrivate = new org.bouncycastle.asn1.sec.ECPrivateKey(keySize, privateKey);
        byte[] x = asnPrivate.getEncoded();

        PrivateKeyInfo asnPrivateX = new PrivateKeyInfo(alg, asnPrivate);
        encodedKey = asnPrivateX.getEncoded();
    }

    
    @Override
    public BigInteger getS() {
        return privateKey;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        return encodedKey;
    }

    @Override
    public ECParameterSpec getParams() {
        return ecParameterSpec;
    }
}
