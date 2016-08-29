/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.util.ArrayList;
import java.util.List;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 *
 * @author jimsch
 */
public class SignMessage extends Message {
    protected List<Signer> signerList = new ArrayList();
    protected byte[] rgbProtected;
    
    public SignMessage() {
        messageTag = messageTag.Sign;
    }
    
    @Override
    protected void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 4) throw new CoseException("Invalid SignMessage structure");
        
        if (obj.get(0).getType() == CBORType.ByteString) {
            if (obj.get(0).GetByteString().length == 0) {
                objProtected = CBORObject.NewMap();
                rgbProtected = new byte[0];
            }
            else {
                rgbProtected = obj.get(0).GetByteString();
                objProtected = CBORObject.DecodeFromBytes(rgbProtected);
                if (objProtected.size() == 0) rgbProtected = new byte[0];
            }
        }
        else throw new CoseException("Invalid SignMessage structure");
        
        if (obj.get(1).getType() == CBORType.Map) {
            objUnprotected = obj.get(1);
        }
        else throw new CoseException("Invalid SignMessage structure");
        
        if (obj.get(2).getType() == CBORType.ByteString) rgbContent = obj.get(2).GetByteString();
        else if (!obj.get(2).isNull()) throw new CoseException("Invalid SignMessage structure");
        
        if (obj.get(3).getType() == CBORType.Array) {
            for (int i=0; i<obj.get(3).size(); i++) {
                Signer signer = new Signer();
                signer.DecodeFromCBORObject(obj.get(3).get(i));
                signerList.add(signer);
            }
        }
        else throw new CoseException("Invalid SignMessage structure");
    }

    @Override
    protected CBORObject EncodeCBORObject() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        
        obj.Add(rgbProtected);
        obj.Add(objUnprotected);
        obj.Add(rgbContent);
        obj.Add(CBORObject.NewArray());
        
        for (Signer r : signerList) {
            obj.get(3).Add(r.EncodeToCBORObject());
        }
        
        return obj;
    }
    
    public void AddSigner(Signer signedBy) {
        signerList.add(signedBy);
    }
    
    public Signer getSigner(int iSigner) {
      return signerList.get(iSigner);
    }
    
    public int getSignerCount() {
        return signerList.size();
    }
    
    public List<Signer> getSignerList() {
        return signerList;
    }
    
    public void sign() throws CoseException {
        if (rgbProtected == null) {
            if (objProtected.size() == 0) rgbProtected = new byte[0];
            else rgbProtected = objProtected.EncodeToBytes();
        }
        
        for (Signer r : signerList) {
            r.sign(rgbProtected, rgbContent);
        }
    }
    
    public boolean validate(Signer signerToUse) throws CoseException {
        for (Signer r : signerList) {
            if (r == signerToUse) {
                return r.validate(rgbProtected, rgbContent);
            }
        }
        
        throw new CoseException("Signer not found");
    }
}
