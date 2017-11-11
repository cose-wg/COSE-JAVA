/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jimsch
 */
public class EncryptMessage extends EncryptCommon {
     protected List<Recipient> recipientList = new ArrayList<>();
   
    public EncryptMessage() {
        this(true);
    }
    
    public EncryptMessage(boolean emitTag) {
        this.emitTag = emitTag;
        messageTag= MessageTag.Encrypt;
        context = "Encrypt";
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
    
    public int getRecipientCount() {
        return recipientList.size();
    }
    
    public byte[] decrypt(Recipient whom) throws CoseException {
        byte[] rgbKey = null;
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        
        for (Recipient r : recipientList) {
            if (r == whom) {
                rgbKey = r.decrypt(alg, whom);
                break;
            }
            else if (r.recipientList.size() > 0) {
                rgbKey = r.decrypt(alg, whom);
                if (rgbKey != null) break;
            }
        }
        
        if (rgbKey == null) throw new CoseException("Recipient key not found");
        return super.decryptWithKey(rgbKey);
    }
    
    public void encrypt() throws CoseException, IllegalStateException, Exception {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        byte[] rgbKey = null;
   
        int recipientTypes = 0;
        
        if (recipientList.isEmpty()) throw new CoseException("No recipients supplied");
        for (Recipient r : recipientList) {
            switch (r.getRecipientType()) {
                case 1:
                    if ((recipientTypes & 1) != 0) throw new CoseException("Cannot have two direct recipients");
                    recipientTypes |= 1;
                    rgbKey = r.getKey(alg);
                    break;
                    
                default:
                    recipientTypes |= 2;
            }
        }
        
        if (recipientTypes == 3) throw new CoseException("Do not mix direct and indirect recipients");
        
        if (recipientTypes == 2) {
            rgbKey = new byte[alg.getKeySize()/8];
            random.nextBytes(rgbKey);
        }
        
        super.encryptWithKey(rgbKey);
        
        for (Recipient r : recipientList) {
            r.SetContent(rgbKey);
            r.encrypt();
        }
    }
    
     @Override
    public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 4) throw new CoseException("Invalid Encrypt structure");
        
        if (obj.get(0).getType() == CBORType.ByteString) {
            if (obj.get(0).GetByteString().length == 0) objProtected = CBORObject.NewMap();
            else objProtected = CBORObject.DecodeFromBytes(obj.get(0).GetByteString());
        }
        else throw new CoseException("Invalid Encrypt structure");
        
        if (obj.get(1).getType() == CBORType.Map) {
            objUnprotected = obj.get(1);
        }
        else throw new CoseException("Invalid Encrypt structure");
        
        if (obj.get(2).getType() == CBORType.ByteString) rgbEncrypt = obj.get(2).GetByteString();
        else if (!obj.get(2).isNull()) throw new CoseException("Invalid Encrypt structure");
        
        if (obj.get(3).getType() == CBORType.Array) {
            for (int i=0; i<obj.get(3).size(); i++) {
                Recipient recipient = new Recipient();
                recipient.DecodeFromCBORObject(obj.get(3).get(i));
                recipientList.add(recipient);
            }
        }
        else throw new CoseException("Invalid Encrypt structure");
    }

     @Override
    protected CBORObject EncodeCBORObject() throws CoseException {
        if (rgbEncrypt == null) throw new CoseException("Compute function not called");
        
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        obj.Add(rgbEncrypt);
        
        CBORObject cnRecipients = CBORObject.NewArray();
        for (Recipient r : recipientList){
            cnRecipients.Add(r.EncodeCBORObject());
        }
        obj.Add(cnRecipients);
        
        return obj;
    }
}
