/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.List;

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
    
    public byte[] decrypt(AlgorithmID algCEK, Recipient recip) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(FindAttribute(HeaderKeys.Algorithm));
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
            
            default:
                throw new CoseException("Unsupported Recipent Algorithm");
        }
    }
    
    public void encrypt() throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(FindAttribute(HeaderKeys.Algorithm));

        switch (alg) {
            case Direct:
                rgbEncrypted = new byte[0];
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
        AlgorithmID alg = AlgorithmID.FromCBOR(FindAttribute(HeaderKeys.Algorithm));
        switch (alg) {
            case Direct:
                return 1;
                
            default:
                return 9;
        }
    }
    
    public byte[] getKey(AlgorithmID algCEK) throws CoseException {
        if (privateKey == null) throw new CoseException("Private key not set for recipient");
        
        AlgorithmID alg = AlgorithmID.FromCBOR(FindAttribute(HeaderKeys.Algorithm));
        
        switch (alg) {
            case Direct:
                if (privateKey.get(KeyKeys.KeyType.AsCBOR()) != KeyKeys.KeyType_Octet) throw new CoseException("Key and algorithm do not agree");
                return privateKey.get(KeyKeys.Octet_K.AsCBOR()).GetByteString();
                
            default:
                throw new CoseException("Recipient Algorithm not supported");
        }
    }
        
    public void SetKey(CBORObject key) {
        privateKey = key;
    }

    public void SetSenderKey(CBORObject key) {
        publicKey = key;
    }
}
