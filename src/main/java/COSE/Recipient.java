/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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
    
    public byte[] decrypt(AlgorithmID algCEK, Recipient recip) throws CoseException {
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
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, "SHA256");

            case HKDF_HMAC_SHA_512:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, "SHA512");

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
                rgbKey = ECDH_GenSecret(privateKey);
                return HKDF(rgbKey, algCEK.getKeySize(), algCEK, "SHA256");
                
            case ECDH_ES_HKDF_512:
            case ECDH_SS_HKDF_512:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenSecret(privateKey);
                return HKDF(rgbKey, algCEK.getKeySize(), algCEK, "SHA512");
                
            case ECDH_ES_HKDF_256_AES_KW_128:
            case ECDH_SS_HKDF_256_AES_KW_128:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 128, AlgorithmID.AES_KW_128, "SHA256");
                return AES_KeyWrap_Decrypt(AlgorithmID.AES_KW_128, rgbKey);
                
            case ECDH_ES_HKDF_256_AES_KW_192:
            case ECDH_SS_HKDF_256_AES_KW_192:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 192, AlgorithmID.AES_KW_192, "SHA256");
                return AES_KeyWrap_Decrypt(AlgorithmID.AES_KW_192, rgbKey);
                
            case ECDH_ES_HKDF_256_AES_KW_256:
            case ECDH_SS_HKDF_256_AES_KW_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 256, AlgorithmID.AES_KW_256, "SHA256");
                return AES_KeyWrap_Decrypt(AlgorithmID.AES_KW_256, rgbKey);
                
            default:
                throw new CoseException("Unsupported Recipent Algorithm");
        }
    }
    
    public void encrypt() throws CoseException {
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
                ECDH_GenEphemeral();
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 128, AlgorithmID.AES_KW_128, "SHA256");
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
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 128, AlgorithmID.AES_KW_128, "SHA256");
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_128, rgbKey);
                break;
                                
            case ECDH_ES_HKDF_256_AES_KW_192:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenEphemeral();
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 192, AlgorithmID.AES_KW_192, "SHA256");
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
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 192, AlgorithmID.AES_KW_192, "SHA256");
                rgbEncrypted = AES_KeyWrap_Encrypt(AlgorithmID.AES_KW_192, rgbKey);
                break;

            case ECDH_ES_HKDF_256_AES_KW_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenEphemeral();
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 256, AlgorithmID.AES_KW_256, "SHA256");
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
                rgbKey = ECDH_GenSecret(privateKey);
                rgbKey = HKDF(rgbKey, 256, AlgorithmID.AES_KW_256, "SHA256");
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
        if (recipientList == null) recipientList = new ArrayList<Recipient>();
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
    
    public byte[] getKey(AlgorithmID algCEK) throws CoseException {
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
                if (!privateKey.HasKeyType(KeyKeys.KeyType_Octet)) throw new CoseException("Key and algorithm do not agree");
                return privateKey.get(KeyKeys.Octet_K).GetByteString();
                
            case ECDH_ES_HKDF_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenEphemeral();
                rgbSecret = ECDH_GenSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, "SHA256");
                
            case ECDH_ES_HKDF_512:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                ECDH_GenEphemeral();
                rgbSecret = ECDH_GenSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, "SHA512");
                
            case ECDH_SS_HKDF_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[256/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbSecret = ECDH_GenSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, "SHA256");
                
            case ECDH_SS_HKDF_512:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) throw new CoseException("Key and algorithm do not agree");
                if (findAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR()) == null) {
                    byte[] rgbAPU = new byte[512/8];
                    random = new SecureRandom();
                    random.nextBytes(rgbAPU);
                    addAttribute(HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR(), CBORObject.FromObject(rgbAPU), Attribute.UNPROTECTED);
                }
                rgbSecret = ECDH_GenSecret(privateKey);
                return HKDF(rgbSecret, algCEK.getKeySize(), algCEK, "SHA512");
                
            case HKDF_HMAC_SHA_256:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, "SHA256");
                 
            case HKDF_HMAC_SHA_512:
                 if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                 return HKDF(privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString(), algCEK.getKeySize(), algCEK, "SHA512");

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

        try {
            Cipher  cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(rgbKey, "AESWrap"));
            return cipher.wrap(new SecretKeySpec(rgbContent, "AES"));
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Key Wrap failure", ex);
        }
    }
    
    private byte[] AES_KeyWrap_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException
    {
        if (rgbKey.length != alg.getKeySize() / 8) throw new CoseException("Key is not the correct size");

        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(rgbKey, "AESWrap"));
            return ((SecretKeySpec)cipher.unwrap(rgbEncrypted, "AES", Cipher.SECRET_KEY)).getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        }
        catch (InvalidKeyException ex) {
            if (ex.getMessage() == "Illegal key size") {
                throw new CoseException("Unsupported key size", ex);
            }
            throw new CoseException("Decryption failure", ex);
        } catch (Exception ex) {
            throw new CoseException("Key Unwrap failure", ex);
        }
    }
    
    private void ECDH_GenEphemeral() throws CoseException {
        OneKey  secretKey = OneKey.generateKey(privateKey.get(KeyKeys.EC2_Curve));
        
        // pack into EPK header
        CBORObject  epk = secretKey.PublicKey().AsCBOR();
        addAttribute(HeaderKeys.ECDH_EPK, epk, Attribute.UNPROTECTED);
        
        // apply as senderKey
        senderKey = secretKey;
    }
    
    private byte[] ECDH_GenSecret(OneKey key) throws CoseException {
        OneKey  epk;
        if (senderKey != null) {
            epk = key;
            key = senderKey;
        } else {
            CBORObject cn = findAttribute(HeaderKeys.ECDH_SPK);
            if (cn == null) {
                cn = findAttribute(HeaderKeys.ECDH_EPK);
            }
            if (cn == null) {
                throw new CoseException("No second party EC key");
            }
            epk = new OneKey(cn);
        }
        
        if (key.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) {
            throw new CoseException("Not an EC2 Key");
        }
        if (epk.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_EC2) {
            throw new CoseException("Not an EC2 Key");
        }
        if (epk.get(KeyKeys.EC2_Curve.AsCBOR()) != key.get(KeyKeys.EC2_Curve.AsCBOR())) {
            throw new CoseException("Curves are not the same");
        }
        
        try {
            PublicKey pubKey = epk.AsPublicKey();
            PrivateKey privKey = key.AsPrivateKey();
            KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
            ecdh.init(privKey);
            ecdh.doPhase(pubKey, true);
            return ecdh.generateSecret();
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Key agreement failure", ex);
        }
    }

    private byte[] HKDF(byte[] secret, int cbitKey, AlgorithmID alg, String digest) throws CoseException {
        final String HMAC_ALG_NAME = "Hmac" + digest;

        byte[]  rgbContext = GetKDFInput(cbitKey, alg);
 
        try {
            Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
            int hashLen = hmac.getMacLength();

            CBORObject  cnSalt = findAttribute(HeaderKeys.HKDF_Salt.AsCBOR());
            byte[] K;
            if (cnSalt == null) {
                K = new byte[hashLen];
            } else {
                K = cnSalt.GetByteString();
            }

            // Perform extract
            hmac.init(new SecretKeySpec(K, HMAC_ALG_NAME));
            byte[] rgbExtract = hmac.doFinal(secret);

            // Perform expand
            hmac.init(new SecretKeySpec(rgbExtract, HMAC_ALG_NAME));
            int c = ((cbitKey + 7)/8 + hashLen-1)/hashLen;
            byte[]  rgbOut = new byte[cbitKey / 8];
            byte[]  T = new byte[hashLen * c];
            byte[]  last = new byte[0];
            for (int i = 0; i < c; i++) {
                hmac.reset();
                hmac.update(last);
                hmac.update(rgbContext);
                hmac.update((byte)(i + 1));
                last = hmac.doFinal();
                System.arraycopy(last, 0, T, i * hashLen, hashLen);
            }
            System.arraycopy(T, 0, rgbOut, 0, cbitKey / 8);
            return rgbOut;
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Derivation failure", ex);
        }
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
