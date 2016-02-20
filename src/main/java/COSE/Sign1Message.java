/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.bouncycastle.crypto.CipherParameters;

/**
 *
 * @author jimsch
 */
public class Sign1Message extends SignCommon {
    byte[] rgbSignature;
    
    public Sign1Message() {
        this(true);
    }
    
    public Sign1Message(boolean emitTag) {
        this.emitTag = emitTag;
        this.contextString = "Signature1";
        this.messageTag = MessageTag.Sign1;
    }
    
    public void sign(CBORObject cnKey) throws CoseException {
        if (rgbContent == null) throw new CoseException("No Content Specified");
        
        CBORObject obj = CBORObject.NewArray();
        obj.Add(contextString);
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        obj.Add(externalData);
        obj.Add(rgbContent);
        
        rgbSignature = computeSignature(obj.EncodeToBytes(), cnKey);
    }
    
    public void sign(CipherParameters key) throws CoseException {
        if (rgbContent == null) throw new CoseException("No Content Specified");
        
        CBORObject obj = CBORObject.NewArray();
        obj.Add(contextString);
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        obj.Add(externalData);
        obj.Add(rgbContent);
        
        rgbSignature = computeSignature(obj.EncodeToBytes(), key);
    }

    public boolean validate(CBORObject cnKey) throws CoseException {
        
        CBORObject obj = CBORObject.NewArray();
        obj.Add(contextString);
        if (objProtected.size() > 0) obj.Add(rgbProtected);
        else obj.Add(CBORObject.FromObject(new byte[0]));
        obj.Add(externalData);
        obj.Add(rgbContent);
        return validateSignature(obj.EncodeToBytes(), rgbSignature, cnKey);
    }
    
    public boolean validate(CipherParameters key) throws CoseException {
        
        CBORObject obj = CBORObject.NewArray();
        obj.Add(contextString);
        if (objProtected.size() > 0) obj.Add(rgbProtected);
        else obj.Add(CBORObject.FromObject(new byte[0]));
        obj.Add(externalData);
        obj.Add(rgbContent);
        return validateSignature(obj.EncodeToBytes(), rgbSignature, key);
    }

    @Override
    protected void DecodeFromCBORObject(CBORObject messageObject) throws CoseException {
        if (messageObject.size() != 4) throw new CoseException("Invalid Sign1 structure");
        
        if (messageObject.get(0).getType() == CBORType.ByteString) {
            if (messageObject.get(0).GetByteString().length == 0) objProtected = CBORObject.NewMap();
            else {
                rgbProtected = messageObject.get(0).GetByteString();
                objProtected = CBORObject.DecodeFromBytes(rgbProtected);
            }
        }
        else throw new CoseException("Invalid Sign1 structure");
        
        if (messageObject.get(1).getType() == CBORType.Map) {
            objUnprotected = messageObject.get(1);
        }
        else throw new CoseException("Invalid Sign1 structure");
        
        if (messageObject.get(2).getType() == CBORType.ByteString) rgbContent = messageObject.get(2).GetByteString();
        else if (!messageObject.get(2).isNull()) throw new CoseException("Invalid Sign1 structure");
        
        if (messageObject.get(3).getType() == CBORType.ByteString) rgbSignature = messageObject.get(3).GetByteString();
        else throw new CoseException("Invalid Sign1 structure");
    }

    @Override
    protected CBORObject EncodeCBORObject() throws CoseException {
        if (rgbSignature == null) throw new CoseException("sign function not called");
       
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        obj.Add(rgbContent);
        obj.Add(rgbSignature);
        
        return obj;
    }
}
