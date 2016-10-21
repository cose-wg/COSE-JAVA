/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.agreement.*;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/**
 * 
 * @author jimsch
 */
public class Recipient extends Message {
    OneKey privateKey;
    private OneKey senderKey;
    byte[] rgbEncrypted;
    List<Recipient> recipientList;
    
    @Override
    public void DecodeFromCBORObject(CBORObject objRecipient) throws CoseException {
        if ((objRecipient.size() != 3) && (objRecipient.size() !=4)) throw new CoseException("Invalid Recipient structure");
        
        if (objRecipient.get(0).getType() == CBORType.ByteString) {
            if (objRecipient.get(0).GetByteString().length == 0) objProtected = CBORObject.NewMap();
            else objProtected = CBORObject.DecodeFromBytes(objRecipient.get(0).GetByteString());
        }
        else throw new CoseException("Invalid Recipient structure");
        
        if (objRecipient.get(1).getType() == CBORType.Map) objUnprotected = objRecipient.get(1);
        else throw new CoseException("Invalid Recipient structure");
        
        if (objRecipient.get(2).getType() == CBORType.ByteString) rgbEncrypted = objRecipient.get(2).GetByteString();
        else throw new CoseException("Invalid Recipient structure");
        
        if (objRecipient.size() == 4) {
            if (objRecipient.get(3).getType() == CBORType.Array) {
                recipientList = new ArrayList<>();
                for (int i=0; i<objRecipient.get(3).size(); i++) {
                    Recipient recipX = new Recipient();
                    recipX.DecodeFromCBORObject(objRecipient.get(3).get(i));
                    recipientList.add(recipX);
                }
            }
            else throw new CoseException("Invalid Recipient structure");
        }
    }

    @Override
    protected CBORObject EncodeCBORObject() throws CoseException {        
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        obj.Add(rgbEncrypted);
        if (recipientList != null) {
            CBORObject objR = CBORObject.NewArray();
            for (Recipient r : recipientList) {
                objR.Add(r.EncodeCBORObject());
            }
            obj.Add(objR);
        }
        
        return obj;
    }
    
    public byte[] decrypt(AlgorithmID algCEK, Recipient recip) throws CoseException, InvalidCipherTextException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        byte[] rgbKey = null;
        
        if (recip != this) {
            for (Recipient r : recipientList) {
                if (recip == r) {
                    rgbKey = r.decrypt(alg, recip);
                    if (rgbKey == null) throw new CoseException("Internal error");
                    break;
                }
                else if (!r.recipientList.isEmpty()) {
                    rgbKey = r.decrypt(alg, recip);
                    if (rgbKey != null) break;
                }
            }
        }
        
        switch (alg) {
            case Direct: // Direct
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Mismatch of algorithm and key");
                return privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
            
            case HKDF_HMAC_SHA_256:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, new SHA256Digest());

            case HKDF_HMAC_SHA_512:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, new SHA512Digest());

            case AES_KW_128:
            case AES_KW_192:
            case AES_KW_256:
                if (rgbKey == null) {
                    if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Key and algorithm do not agree");
                    rgbKey = privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
                }
                else if (privateKey != null) throw new CoseException("Key and algorithm do not agree");
                return AES_KeyWrap_Decrypt(alg, rgbKey);
                
            case ECDH_ES_HKDF_256:
            case ECDH_SS_HKDF_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenerateSecret(privateKey);
                return HKDF(rgbKey, algCEK.getKeySize(), algCEK, new SHA256Digest());
                
            case ECDH_ES_HKDF_512:
            case ECDH_SS_HKDF_512:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenerateSecret(privateKey);
                return HKDF(rgbKey, algCEK.getKeySize(), algCEK, new SHA512Digest());
                
            case ECDH_ES_HKDF_256_AES_KW_128:
            case ECDH_SS_HKDF_256_AES_KW_128:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 128, AlgorithmID.AES_KW_128, new SHA256Digest());
                return AES_KeyWrap_Decrypt(AlgorithmID.AES_KW_128, rgbKey);
                
            case ECDH_ES_HKDF_256_AES_KW_192:
            case ECDH_SS_HKDF_256_AES_KW_192:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 192, AlgorithmID.AES_KW_192, new SHA256Digest());
                return AES_KeyWrap_Decrypt(AlgorithmID.AES_KW_192, rgbKey);
                
            case ECDH_ES_HKDF_256_AES_KW_256:
            case ECDH_SS_HKDF_256_AES_KW_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 256, AlgorithmID.AES_KW_256, new SHA256Digest());
                return AES_KeyWrap_Decrypt(AlgorithmID.AES_KW_256, rgbKey);
                
            default:
                throw new CoseException("Unsupported Recipent Algorithm");
        }
    }
    
    public void encrypt() throws CoseException, Exception {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        byte[] rgbKey = null;
        SecureRandom random;
        
        int recipientTypes = 0;
        
        if (recipientList != null && !recipientList.isEmpty()) {
            if (privateKey != null) throw new CoseException("Cannot have dependent recipients if key is specified");
            
            for (Recipient r : recipientList) {
                switch (r.getRecipientType()) {
                    case 1:
                        if ((recipientTypes & 1) != 0) throw new CoseException("Cannot have two direct recipients");
                        recipientTypes |= 1;
                        rgbKey = r.getKey(alg);
                        break;
                        
                    default:
                        recipientTypes |= 2;
                        break;
                }
            }
        }
        
        if (recipientTypes == 3) throw new CoseException("Do not mix direct and indirect recipients");
        
        if (recipientTypes == 2) {
            rgbKey = new byte[alg.getKeySize()/8];
            random = new SecureRandom();
            random.nextBytes(rgbKey);
        }

        switch (alg) {
            case Direct:
            case HKDF_HMAC_SHA_256:
            case HKDF_HMAC_SHA_512:
                rgbEncrypted = new byte[0];
                break;
                
            case AES_KW_128:
            case AES_KW_192:
            case AES_KW_256:
                if (rgbKey == null) {
                    if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Key and algorithm do not agree");
                    rgbKey = privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
                }
                rgbEncrypted = AES_KeyWrap_Encrypt(alg, rgbKey);
                break;
                
            case ECDH_ES_HKDF_256:
            case ECDH_ES_HKDF_512:
            case ECDH_SS_HKDF_256:
            case ECDH_SS_HKDF_512:
                rgbEncrypted = new byte[0];
                break;
                
            case ECDH_ES_HKDF_256_AES_KW_128:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenerateEphemeral();
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 128, AlgorithmID.AES_KW_128, new SHA256Digest());
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_128, rgbKey);
                break;

            case ECDH_SS_HKDF_256_AES_KW_128:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[256/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 128, AlgorithmID.AES_KW_128, new SHA256Digest());
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_128, rgbKey);
                break;
                                
            case ECDH_ES_HKDF_256_AES_KW_192:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenerateEphemeral();
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 192, AlgorithmID.AES_KW_192, new SHA256Digest());
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_192, rgbKey);
                break;

            case ECDH_SS_HKDF_256_AES_KW_192:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[256/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 192, AlgorithmID.AES_KW_192, new SHA256Digest());
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_192, rgbKey);
                break;

            case ECDH_ES_HKDF_256_AES_KW_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenerateEphemeral();
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 256, AlgorithmID.AES_KW_256, new SHA256Digest());
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_256, rgbKey);
                break;

            case ECDH_SS_HKDF_256_AES_KW_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[256/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbKey = ECDH_GenerateSecret(privateKey);
                rgbKey = HKDF(rgbKey, 256, AlgorithmID.AES_KW_256, new SHA256Digest());
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_256, rgbKey);
                break;

            default:
                throw new CoseException("Unsupported Recipient Algorithm");
        }
        
        if (recipientList != null) {
            for (Recipient r : recipientList) {
                r.SetContent(rgbKey);
                r.encrypt();
            }
        }
    }

    public void addRecipient(Recipient recipient) {
        if (recipientList == null) recipientList = new ArrayList();
        recipientList.add(recipient);
    }
    
    public List<Recipient> getRecipientList() {
        return recipientList;
    }

    public Recipient getRecipient(int iRecipient) {
        return recipientList.get(iRecipient);
    }
    
    public int getRecipientCount() {
        return recipientList.size();
    }
    
    public int getRecipientType() throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        switch (alg) {
            case Direct:
            case HKDF_HMAC_SHA_256:
            case HKDF_HMAC_SHA_512:
            case ECDH_ES_HKDF_256:
            case ECDH_ES_HKDF_512:
            case ECDH_SS_HKDF_256:
            case ECDH_SS_HKDF_512:
                return 1;
                
            default:
                return 9;
        }
    }
    
    public byte[] getKey(AlgorithmID algCEK) throws CoseException, Exception {
        byte[] rgbSecret;
        SecureRandom random;
        
        if (privateKey == null) throw new CoseException("Private key not set for recipient");
        
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        
        switch (alg) {
            case Direct:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Key and algorithm do not agree");
                return privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
                
            case AES_KW_128:
            case AES_KW_192:
            case AES_KW_256:
                throw new Exception("Internal Error");
                
            case ECDH_ES_HKDF_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenerateEphemeral();
                rgbSecret = ECDH_GenerateSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, new SHA256Digest());
                
            case ECDH_ES_HKDF_512:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenerateEphemeral();
                rgbSecret = ECDH_GenerateSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, new SHA512Digest());
                
            case ECDH_SS_HKDF_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[256/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbSecret = ECDH_GenerateSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, new SHA256Digest());
                
            case ECDH_SS_HKDF_512:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[512/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbSecret = ECDH_GenerateSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, new SHA512Digest());
                
            case HKDF_HMAC_SHA_256:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, new SHA256Digest());
                 
            case HKDF_HMAC_SHA_512:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, new SHA512Digest());

            default:
                throw new CoseException("Recipient Algorithm not supported");
        }
    }
        
    /**
     * Set the key for encrypting/decrypting the recipient key.
     * 
     * @param key private key for encrypting or decrypting
     * @exception CoseException Internal COSE package error.
     * @deprecated In COSE 0.9.1, use SetKey(OneKey)
     */
    @Deprecated
    public void SetKey(CBORObject key) throws CoseException {
        privateKey = new OneKey(key);
    }
    
    /**
     * Set the key for encrypting/decrypting the recipient key.
     * 
     * @param key private key for encrypting or decrypting
     */
    public void SetKey(OneKey key) {
        privateKey = key;
    }

    @Deprecated
    public void SetSenderKey(CBORObject key) throws CoseException {
        senderKey = new OneKey(key);
    }
    
    public void SetSenderKey(OneKey key) {
        senderKey = key;
    }
    
    private byte[] AES_KeyWrap_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException
    {
        if (rgbKey.length != alg.getKeySize() / 8) throw new CoseException("Key is not the correct size");

        AESWrapEngine foo = new AESWrapEngine();
        KeyParameter parameters = new KeyParameter(rgbKey);
        foo.init(true, parameters);
        return foo.wrap(rgbContent, 0, rgbContent.length);
    }
    
    private byte[] AES_KeyWrap_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, InvalidCipherTextException
    {
        if (rgbKey.length != alg.getKeySize() / 8) throw new CoseException("Key is not the correct size");

        AESWrapEngine foo = new AESWrapEngine();
        KeyParameter parameters = new KeyParameter(rgbKey);
        foo.init(false, parameters);
        return foo.unwrap(rgbEncrypted, 0, rgbEncrypted.length);
    }
    
    
    private void ECDH_GenerateEphemeral() throws CoseException
    {
        X9ECParameters p = privateKey.GetCurve();
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());

        ECKeyPairGenerator pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, null);
        pGen.init(genParam);

        AsymmetricCipherKeyPair p1 = pGen.generateKeyPair();

        CBORObject epk = CBORObject.NewMap();
        epk.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        epk.Add(KeyKeys.EC2_Curve.AsCBOR(), privateKey.get(KeyKeys.EC2_Curve.AsCBOR()));
        ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.getPublic();

        byte[] rgbEncoded = priv.getQ().normalize().getEncoded(true);
        byte[] X = new byte[rgbEncoded.length - 1];
        System.arraycopy(rgbEncoded, 1, X, 0, X.length);
        epk.Add(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(X));
        epk.Add(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject((rgbEncoded[0] & 1) == 1));
        addAttribute(HeaderKeys.ECDH_EPK, epk, Attribute.UNPROTECTED);
        
        OneKey secretKey = new OneKey();
        secretKey.add(KeyKeys.KeyType, KeyKeys.KeyType_EC2);
        secretKey.add(KeyKeys.EC2_Curve, privateKey.get(KeyKeys.EC2_Curve.AsCBOR()));
        secretKey.add(KeyKeys.EC2_X, CBORObject.FromObject(X));
        secretKey.add(KeyKeys.EC2_Y, CBORObject.FromObject((rgbEncoded[0] & 1) == 1));
        ECPrivateKeyParameters priv1 = (ECPrivateKeyParameters) p1.getPrivate();
        secretKey.add(KeyKeys.EC2_D, CBORObject.FromObject(BigIntegers.asUnsignedByteArray( priv1.getD())));
        
        senderKey = secretKey;
    }

    private byte[] ECDH_GenerateSecret(OneKey key) throws CoseException
    {
        OneKey epk;
               
        if (senderKey != null) {
            epk = key;
            key = senderKey;
        }
        else {
            CBORObject cn;
            cn = findAttribute(HeaderKeys.ECDH_SPK);
            if (cn == null) {
                cn = findAttribute(HeaderKeys.ECDH_EPK);
            }
            if (cn == null) throw new CoseException("No second party EC key");
            epk = new OneKey(cn);
        }
        
        if (key.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Not an EC2 Key");
        if (epk.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Not an EC2 Key");
        if (epk.get(KeyKeys.EC2_Curve.AsCBOR()) != key.get(KeyKeys.EC2_Curve.AsCBOR())) throw new CoseException("Curves are not the same");
        
        X9ECParameters p = epk.GetCurve();
        ECDomainParameters parameters = new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH());
        
        ECPoint pubPoint;
        
        CBORObject y = epk.get(KeyKeys.EC2_Y.AsCBOR());
        byte[] x = epk.get(KeyKeys.EC2_X.AsCBOR()).GetByteString();
        if (y.getType() == CBORType.Boolean) {
            byte[] X = epk.get(KeyKeys.EC2_X.AsCBOR()).GetByteString();
            byte[] rgb = new byte[X.length + 1];
            System.arraycopy(X, 0, rgb, 1, X.length);
            rgb[0] = (byte) (2 + (y.AsBoolean() ? 1 : 0));
            pubPoint = p.getCurve().decodePoint(rgb);
        }
        else {
            pubPoint = p.getCurve().createPoint(new BigInteger(1, x), new BigInteger(1, y.GetByteString()));
        }
        
        ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(new BigInteger(1, key.get(KeyKeys.EC2_D.AsCBOR()).GetByteString()), parameters);
        BasicAgreement e1 = new ECDHBasicAgreement();
        e1.init(priv);
        
        BigInteger k1 = e1.calculateAgreement(pub);
        return BigIntegers.asUnsignedByteArray((p.getCurve().getFieldSize()+7)/8, k1);
    }
    
    private byte[] HKDF(byte[] secret, int cbitKey, AlgorithmID algorithmID, Digest digest)
    {
        byte[] rgbContext = GetKDFInput(cbitKey, algorithmID);
        
        CBORObject obj =  findAttribute(HeaderKeys.HKDF_Salt.AsCBOR());
        
        //  Perform the Extract phase
        
        HMac mac = new HMac(digest);
        
        int hashLength = digest.getDigestSize();
        int c = ((cbitKey + 7)/8 + hashLength-1)/hashLength;
        
        byte[] K = new byte[digest.getDigestSize()];
        if (obj != null) K = obj.GetByteString();
        KeyParameter key = new KeyParameter(K);
        mac.init(key);
        mac.update(secret, 0, secret.length);
        
        byte[] rgbExtract = new byte[hashLength];
        mac.doFinal(rgbExtract, 0);
        
        //  Now do the Expand phase
        
        byte[] rgbOut = new byte[cbitKey/8];
        byte[] rgbT = new byte[hashLength * c];
        mac = new HMac(digest);
        key = new KeyParameter(rgbExtract);
        mac.init(key);
        byte[] rgbLast = new byte[0];
        byte[] rgbHash2 = new byte[hashLength];
        
        for (int i=0; i<c; i++) {
            mac.reset();
            mac.update(rgbLast, 0, rgbLast.length);
            mac.update(rgbContext, 0, rgbContext.length);
            mac.update((byte) (i + 1));
            
            rgbLast = rgbHash2;
            mac.doFinal(rgbLast, 0);
            System.arraycopy(rgbLast, 0, rgbT, i*hashLength, hashLength);
        }
        
        System.arraycopy(rgbT, 0, rgbOut, 0, cbitKey/8);
        return rgbOut;
    }
    
    private byte[] GetKDFInput(int cbitKey, AlgorithmID algorithmID) {
        CBORObject obj;
        
        CBORObject contextArray = CBORObject.NewArray();
        
        //  First element is - algorithm ID
        contextArray.Add(algorithmID.AsCBOR());
        
        //  Second item is - Party U info
        CBORObject info = CBORObject.NewArray();
        contextArray.Add(info);
        obj = findAttribute(HeaderKeys.HKDF_Context_PartyU_ID.AsCBOR());
        if (obj != null) info.Add(obj);
        else info.Add(null);
        obj = findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR());
        if (obj != null) info.Add(obj);
        else info.Add(null);
        obj = findAttribute(HeaderKeys.HKDF_Context_PartyU_Other.AsCBOR());
        if (obj != null) info.Add(obj);
        else info.Add(null);

        //  third element is - Party V info
        info = CBORObject.NewArray();
        contextArray.Add(info);
        obj = findAttribute(HeaderKeys.HKDF_Context_PartyV_ID.AsCBOR());
        if (obj != null) info.Add(obj);
        else info.Add(null);
        obj = findAttribute(HeaderKeys.HKDF_Context_PartyV_nonce.AsCBOR());
        if (obj != null) info.Add(obj);
        else info.Add(null);
        obj = findAttribute(HeaderKeys.HKDF_Context_PartyV_Other.AsCBOR());
        if (obj != null) info.Add(obj);
        else info.Add(null);

        //  fourth element is - Supplimental Public Info
        info = CBORObject.NewArray();
        contextArray.Add(info);
        info.Add(CBORObject.FromObject(cbitKey));
        if (objProtected.size()== 0) info.Add(new byte[0]);
        else info.Add(objProtected.EncodeToBytes());
        obj = findAttribute(HeaderKeys.HKDF_SuppPub_Other.AsCBOR());
        if (obj != null) info.Add(obj);

        //  Fifth element is - Supplimental Private Info
        obj = findAttribute(HeaderKeys.HKDF_SuppPriv_Other.AsCBOR());
        if (obj != null) contextArray.Add(obj);

        return contextArray.EncodeToBytes();
    }
}
