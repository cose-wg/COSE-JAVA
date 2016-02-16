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
    CBORObject myKey;
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
    
    public byte[] Decrypt(int cbitKeyOut, CBORObject algKeyOut) throws CoseException {
        CBORObject alg = FindAttribute(CBORObject.FromObject(1));
        
        switch (alg.AsInt32()) {
            case -6: // Direct
                if (myKey.get(CBORObject.FromObject(1)).AsInt32() != 4) return null;
                return myKey.get(CBORObject.FromObject(-1)).GetByteString();
            
            default:
                throw new CoseException("Unsupported Recipent Algorithm");
        }
    }
    
    public void SetKey(CBORObject key) {
        myKey = key;
    }
}
