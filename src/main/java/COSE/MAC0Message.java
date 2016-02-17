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
public class MAC0Message extends MacCommon {
    
    public MAC0Message() {
        super();
        strContext = "MAC0";
        messageTag = 996;
    }
    
    public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 4) throw new CoseException("Invalid MAC0 structure");
        
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
    
    public void Create(byte[] rgbKey) throws CoseException {
        super.Create(rgbKey);
    }
    
    public boolean Validate(byte[] rgbKey) throws CoseException {
        return super.Validate(rgbKey);
    }
            
}
