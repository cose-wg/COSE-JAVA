/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 *
 * @author jimsch
 */
public class MACMessage extends MacCommon {
    
    public MACMessage() {
        super();
        strContext = "MAC";
        messageTag = 994;
    }
    
    public List<Recipient> getRecipientList() {
        return recipientList;
    }
    
    public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 5) throw new CoseException("Invalid MAC structure");
        
        if (obj.get(0).getType() == CBORType.ByteString) {
            if (obj.get(0).GetByteString().length == 0) objProtected = CBORObject.NewMap();
            else objProtected = CBORObject.DecodeFromBytes(obj.get(0).GetByteString());
        }
        else throw new CoseException("Invalid MAC structure");
        
        if (obj.get(1).getType() == CBORType.Map) {
            objUnprotected = obj.get(1);
        }
        else throw new CoseException("Invalid MAC structure");
        
        if (obj.get(2).getType() == CBORType.ByteString) rgbContent = obj.get(2).GetByteString();
        else if (!obj.get(2).isNull()) throw new CoseException("Invalid MAC struture");
        
        if (obj.get(3).getType() == CBORType.ByteString) rgbTag = obj.get(3).GetByteString();
        else throw new CoseException("Invalid MAC structure");
        
        if (obj.get(4).getType() == CBORType.Array) {
            for (int i=0; i<obj.get(4).size(); i++) {
                Recipient recipient = new Recipient();
                recipient.DecodeFromCBORObject(obj.get(4).get(i));
                recipientList.add(recipient);
            }
        }
        else throw new CoseException("Invalid MAC structure");
    }

    protected CBORObject EncodeCBORObject() throws CoseException {
        if (rgbTag == null) throw new CoseException("Compute function not called");
        
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        obj.Add(rgbContent);
        obj.Add(rgbTag);
        
        return obj;
    }
    
    public Recipient GetRecipient(int iRecipient) {
        return recipientList.get(iRecipient);
    }
    
    public boolean Validate(Recipient recipientToUse) throws CoseException {
        byte[] rgbKey = null;
        int cbitKey = 0;
        AlgorithmID alg = AlgorithmID.FromCBOR(FindAttribute(HeaderKeys.Algorithm));
        
        
        for (Recipient recipient : recipientList ) {
            
            if (recipientToUse == null) {
                try {
                    rgbKey = recipient.decrypt(alg, recipientToUse);
                }
                catch(CoseException e) {
                }
            }
            else if (recipientToUse == recipient) {
                try {
                    rgbKey = recipient.decrypt(alg, recipientToUse);
                }
                catch(CoseException e) {
                }
                if (rgbKey == null) break;
            }
            
            if (rgbKey != null) {
                return super.Validate(rgbKey);
            }
        }
        throw new CoseException("Usable recipient not found");
    }
}
 