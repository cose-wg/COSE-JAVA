/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.List;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author jimsch
 */
public class Recipient extends Message {
    CBORObject privateKey;
    CBORObject publicKey;
    byte[] rgbEncrypted;
    List<Recipient> recipientList;
    
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
                for (int i=0; i<objRecipient.get(3).size(); i++) {
                    Recipient recipX = new Recipient();
                    recipX.DecodeFromCBORObject(objRecipient.get(3).get(i));
                    recipientList.add(recipX);
                }
            }
            else throw new CoseException("Invalid Recipient structure");
        }
    }

    protected CBORObject EncodeCBORObject() throws CoseException {        
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        obj.Add(rgbEncrypted);
        
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
                }
                else if (r.recipientList.size() != 0) {
                    rgbKey = r.decrypt(alg, recip);
                    if (rgbKey != null) break;
                }
            }
        }
        
        switch (alg) {
            case Direct: // Direct
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Mismatch of algorithm and key");
                return privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
            
            case AES_KW_128:
            case AES_KW_192:
            case AES_KW_256:
               if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Key and algorithm do not agree");
                rgbKey = privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
                return AES_KeyWrap_Decrypt(alg, rgbKey);

            default:
                throw new CoseException("Unsupported Recipent Algorithm");
        }
    }
    
    public void encrypt() throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        byte[] rgbKey;

        switch (alg) {
            case Direct:
                rgbEncrypted = new byte[0];
                break;
                
            case AES_KW_128:
            case AES_KW_192:
            case AES_KW_256:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Key and algorithm do not agree");
                rgbKey = privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
                rgbEncrypted = AES_KeyWrap_Encrypt(alg, rgbKey);
                break;
                
            default:
                throw new CoseException("Unsupported Recipient Algorithm");
        }
    }

    public void addRecipient(Recipient recipient) {
        recipientList.add(recipient);
    }
    
    public List<Recipient> getRecipientList() {
        return recipientList;
    }

    public Recipient getRecipient(int iRecipient) {
        return recipientList.get(iRecipient);
    }
    
    public int getRecipientType() throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        switch (alg) {
            case Direct:
                return 1;
                
            default:
                return 9;
        }
    }
    
    public byte[] getKey(AlgorithmID algCEK) throws CoseException, Exception {
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
                
            default:
                throw new CoseException("Recipient Algorithm not supported");
        }
    }
        
    public void SetKey(CBORObject key) {
        privateKey = key;
    }

    public void SetSenderKey(CBORObject key, int options) {
        publicKey = key;
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
    
}
