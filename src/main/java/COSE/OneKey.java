/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
    
    public CBORObject get(KeyKeys keyValue) {
        return keyMap.get(keyValue.AsCBOR());
    }
    
    public CBORObject get(CBORObject keyValue) throws CoseException {
        if ((keyValue.getType() != CBORType.Number) && (keyValue.getType() != CBORType.TextString)) throw new CoseException("keyValue type is incorrect");
        return keyMap.get(keyValue);
    }
 
    /**
     * Compares the key's assigned algorithm with the provided value, indicating if the values are the
     * same.
     * 
     * @param algorithmId
     *          the algorithm to compare or {@code null} to check for no assignment.
     * @return {@code true} if the current key has the provided algorithm assigned, or {@code false}
     *         otherwise
     */
    public boolean HasAlgorithmID(AlgorithmID algorithmId) {
        CBORObject thisObj = get(KeyKeys.Algorithm);
        CBORObject thatObj = (algorithmId == null ? null : algorithmId.AsCBOR());
        boolean result;

        if (thatObj == null) {
            result = (thisObj == null);
        } else {
            result = thatObj.equals(thisObj);
        }
        return result;
    }

    /**
     * Compares the key's assigned identifier with the provided value, indicating if the values are
     * the same.
     * 
     * @param id
     *          the identifier to compare or {@code null} to check for no assignment.
     * @return {@code true} if the current key has the provided identifier assigned, or {@code false}
     *         otherwise
     */
    public boolean HasKeyID(String id) {
        CBORObject thatObj = (id == null) ? null : CBORObject.FromObject(id);
        CBORObject thisObj = get(KeyKeys.KeyId);
        boolean result;
        if (thatObj == null) {
            result = (thisObj == null);
        } else {
            result = thatObj.equals(thisObj);
        }    
        return result;
    }

    /**
    * Compares the key's assigned key type with the provided value, indicating if the values are the
    * same.
    * 
    * @param keyTypeObj
    *          the key type to compare or {@code null} to check for no assignment.
    * @return {@code true} if the current key has the provided identifier assigned, or {@code false}
    *         otherwise
    */
    public boolean HasKeyType(CBORObject keyTypeObj) {
        CBORObject thatObj = keyTypeObj;
        CBORObject thisObj = get(KeyKeys.KeyType);
        boolean result;
        if (thatObj == null) {
            result = (thisObj == null);
        } else {
            result = thatObj.equals(thisObj);
        }
        return result;
    }
  
    /**
     * Compares the key's assigned key operations with the provided value, indicating if the provided
     * value was found in the key operation values assigned to the key.
     * 
     * @param that
     *          the integer operation value to attempt to find in the values provided by the key or
     *          {@code null} to check for no assignment.
     * @return {@code true} if the current key has the provided value assigned, or {@code false}
     *         otherwise
     */
    public boolean HasKeyOp(Integer that) {
        CBORObject thisObj = get(KeyKeys.Key_Ops);
        boolean result;
        if (that == null) {
            result = (thisObj == null);
        } else {
            result = false;
            if (thisObj.getType() == CBORType.Number) {
                if (thisObj.AsInt32() == that) {
                    result = true;
                }
            } else if (thisObj.getType() == CBORType.Array) {
                for (int i = 0; i < thisObj.size(); i++) {
                    if ((thisObj.get(i).getType() == CBORType.Number) && (thisObj.get(i).AsInt32() == that)) {
                        result = true;
                        break;
                    }
               }
            }
        }
        return result;
    }

    private void CheckKeyState() throws CoseException {
        CBORObject val;
        
        //  Must have a key type
        val = OneKey.this.get(KeyKeys.KeyType);
        if ((val == null) || (val.getType() != CBORType.Number)) throw new CoseException("Missing or incorrect key type field");
        
        if (val.equals(KeyKeys.KeyType_Octet)) {
            val = OneKey.this.get(KeyKeys.Octet_K);
            if ((val== null) || (val.getType() != CBORType.ByteString)) throw new CoseException("Malformed key structure");
        }
        else if (val.equals(KeyKeys.KeyType_EC2)) {
            boolean privateKey = false;
            
            val = OneKey.this.get(KeyKeys.EC2_D);
            if (val != null) {
                if (val.getType() != CBORType.ByteString) throw new CoseException("Malformed key structure");
                privateKey = true;
            }
            
            val = OneKey.this.get(KeyKeys.EC2_X);
            if (val == null) {
                if (!privateKey) throw new CoseException("Malformed key structure");
            }
            else if (val.getType() != CBORType.ByteString) throw new CoseException("Malformed key structure");
            
            val = OneKey.this.get(KeyKeys.EC2_Y);
            if (val == null) {
                if (!privateKey) throw new CoseException("Malformed key structure");
            }
            else if ((val.getType() != CBORType.ByteString) && (val.getType() != CBORType.Boolean)) throw new CoseException("Malformed key structure");
        }
        else throw new CoseException("Unsupported key type");
    }

    public X9ECParameters GetCurve() throws CoseException {    
        if (OneKey.this.get(KeyKeys.KeyType) != KeyKeys.KeyType_EC2) throw new CoseException("Not an EC2 key");
        CBORObject cnCurve = OneKey.this.get(KeyKeys.EC2_Curve);
        
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
    static public OneKey generateKey(CBORObject curve) throws CoseException {
        String curveName;
        
        switch (curve.AsInt32()) {
            case 1:
                curveName = "P-256";
                break;
            
            case 2:
                curveName = "P-384";
                break;
            
            case 3:
                curveName = "P-521";
                break;

            default:
                throw new CoseException("Unkonwn curve");
        }

        OneKey returnThis = generateECDHKey(curveName, curve);
        return returnThis;
    }
    
    static private OneKey generateECDHKey(String curveName, CBORObject curve) {
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
        byte[] rgbD = keyPrivate.getD().toByteArray();

        OneKey key = new OneKey();

        key.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
        key.add(KeyKeys.EC2_Curve, curve);
        key.add(KeyKeys.EC2_X, CBORObject.FromObject(rgbX));
        key.add(KeyKeys.EC2_Y, CBORObject.FromObject(rgbY));
        key.add(KeyKeys.EC2_D, CBORObject.FromObject(rgbD));

        return key;
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
    
    /**
     * Create a OneKey object with only the public fields.  Filters out the 
     * private key fields but leaves all positive number labels and text labels
     * along with negative number labels that are public fields.
     * 
     * @return public version of the key
     */
    public OneKey PublicKey()
    {
        OneKey newKey = new OneKey();
        CBORObject val = this.get(KeyKeys.KeyType);
        if (val.equals(KeyKeys.KeyType_Octet)) {
            return null;
        }
        else if (val.equals(KeyKeys.KeyType_EC2)) {
            newKey.add(KeyKeys.EC2_Curve, get(KeyKeys.EC2_Curve));
            newKey.add(KeyKeys.EC2_X, get(KeyKeys.EC2_X));
            newKey.add(KeyKeys.EC2_Y, get(KeyKeys.EC2_Y));
        }
        /*
        else if (val.equals(KeyKeys.KeyType_OKP)) {
            newKey.add(KeyKeys.OKP_Curve, get(KeyKeys.OKP_Curve));
            newKey.add(KeyKeys.OKP_X, get(KeyKeys.OKP_X));
        }
        */
        else {
            return null;
        }

        for (CBORObject obj : keyMap.getKeys()) {
            val = keyMap.get(obj);
            if (obj.getType() == CBORType.Number) {
                if (obj.AsInt32() > 0) {
                    newKey.add(obj, val);
                }
            }
            else if (obj.getType() == CBORType.TextString) {
                newKey.add(obj, val);
            }
        }
        return newKey;
    }
    
    /**
     * Encode to a byte string
     * 
     * @return encoded object as bytes.
     */
    public byte[] EncodeToBytes()
    {
        return keyMap.EncodeToBytes();
    }
    
    /**
     * Return the key as a CBOR object
     * 
     * @return 
     */
    public CBORObject AsCBOR()
    {
        return keyMap;
    }
    
    /**
     * Return a java.security.PublicKey that is the same as the OneKey key
     * 
     * @return the key
     * @throws CoseException If there is a conversion error
     */
    public PublicKey AsPublicKey() throws CoseException
    {
        if (get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2))
        {
            try {
                return new ECPublicKey(this);
            }
            catch (IOException e) {
                throw new CoseException("Internal Error encoding the key");
            }
        }
        throw new CoseException("Cannot convert key as key type is not converted");
    }
    
    /**
     * Return a java.security.PrivateKey that is the same as the OneKey key
     * 
     * @return the key
     * @throws CoseException if there is a conversion error
     */
    public PrivateKey AsPrivateKey() throws CoseException
    {
        if (get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2))
        {
            try {
                return new ECPrivateKey(this);
            } catch (IOException ex) {
                throw new CoseException("Internal error encoding the key");
            }
        }
        throw new CoseException("Cannot convert key as key type is not converted");
    }
    
    private Object UserData;
    
    /**
     * Return the user data field.
     * 
     * The user data object allows for an application to associate a piece of arbitrary
     * data with a key and retrieve it later.  
     * @return
     */
    public Object getUserData() {
        return UserData;
    }
    
    /**
     * Set the user data field.
     * 
     * The user data field allows for an application to associate a piece of arbitrary
     * data with a key and retrieve it later.
     * @param newData Data field to be saved.
     */
    public void setUserData(Object newData) {
        UserData = newData;
    }
}
