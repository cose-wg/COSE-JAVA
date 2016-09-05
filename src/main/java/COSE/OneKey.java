/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.*;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
/**
 *
 * @author jimsch
 */
public class OneKey {

    protected CBORObject keyMap;
    
    public OneKey() {
        keyMap = CBORObject.NewMap();
    }
    
    public OneKey(CBORObject keyData) throws CoseException {
        if (keyData.getType() != CBORType.Map) throw new CoseException("Key data is malformed");
        
        keyMap = keyData;
        CheckKeyState();
    }
    
    public void add(KeyKeys keyValue, CBORObject value) {
        keyMap.Add(keyValue.AsCBOR(), value);
    }
    
    public void add(CBORObject keyValue, CBORObject value) {
        keyMap.Add(keyValue, value);
    }
    
    public CBORObject getValue(KeyKeys keyValue) {
        return keyMap.get(keyValue.AsCBOR());
    }
    
    public CBORObject getValue(CBORObject keyValue) throws CoseException {
        if ((keyValue.getType() != CBORType.Number) && (keyValue.getType() != CBORType.TextString)) throw new CoseException("keyValue type is incorrect");
        return keyMap.get(keyValue);
    }
    
    private void CheckKeyState() throws CoseException {
        CBORObject val;
        
        //  Must have a key type
        val = getValue(KeyKeys.KeyType);
        if ((val == null) || (val.getType() != CBORType.Number)) throw new CoseException("Missing or incorrect key type field");
        
        if (val.equals(KeyKeys.KeyType_Octet)) {
            val = getValue(KeyKeys.Octet_K);
            if ((val== null) || (val.getType() != CBORType.ByteString)) throw new CoseException("Malformed key structure");
        }
        else if (val.equals(KeyKeys.KeyType_EC2)) {
            val = getValue(KeyKeys.EC2_X);
            if ((val == null) || (val.getType() != CBORType.ByteString)) throw new CoseException("Malformed key structure");
            val = getValue(KeyKeys.EC2_Y);
            if ((val == null) || 
                ((val.getType() != CBORType.ByteString) && (val.getType() != CBORType.Boolean))) throw new CoseException("Malformed key structure");
        }
        else throw new CoseException("Unsupported key type");
    }

    public X9ECParameters GetCurve() throws CoseException {    
        if (getValue(KeyKeys.KeyType) != KeyKeys.KeyType_EC2) throw new CoseException("Not an EC2 key");
        CBORObject cnCurve = getValue(KeyKeys.EC2_Curve);
        
        if (cnCurve == KeyKeys.EC2_P256) return NISTNamedCurves.getByName("P-256");
        if (cnCurve == KeyKeys.EC2_P384) return NISTNamedCurves.getByName("P-384");
        if (cnCurve == KeyKeys.EC2_P521) return NISTNamedCurves.getByName("P-521");
        throw new CoseException("Unsupported curve " + cnCurve);
    }
    
    static public OneKey generateKey(AlgorithmID algorithm) throws CoseException {
        OneKey returnThis = null;
        switch(algorithm) {
            case ECDSA_256:
                returnThis = generateECDSAKey("P-256", KeyKeys.EC2_P256); 
                break;
                
            case ECDSA_384:
                returnThis = generateECDSAKey("P-384", KeyKeys.EC2_P384);
                break;
                
            case ECDSA_512:
                returnThis = generateECDSAKey("P-521", KeyKeys.EC2_P521);
                break;
                
            default:
                throw new CoseException("Unknown algorithm");
        }
        
        returnThis.add(KeyKeys.Algorithm, algorithm.AsCBOR());
        return returnThis;
    }
    
    static private OneKey generateECDSAKey(String curveName, CBORObject curve) {                
        X9ECParameters p = NISTNamedCurves.getByName(curveName);
        
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);

        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();

        ECPublicKeyParameters keyPublic = (ECPublicKeyParameters) p1.getPublic();
        ECPrivateKeyParameters keyPrivate = (ECPrivateKeyParameters) p1.getPrivate();

        byte[] rgbX = keyPublic.getQ().normalize().getXCoord().getEncoded();
        byte[] rgbY = keyPublic.getQ().normalize().getYCoord().getEncoded();
        boolean signY = true;
        byte[] rgbD = keyPrivate.getD().toByteArray();

        OneKey key = new OneKey();

        key.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
        key.add(KeyKeys.EC2_Curve, curve);
        key.add(KeyKeys.EC2_X, CBORObject.FromObject(rgbX));
        key.add(KeyKeys.EC2_Y, CBORObject.FromObject(rgbY));
        key.add(KeyKeys.EC2_D, CBORObject.FromObject(rgbD));

        return key;        
    }
}
