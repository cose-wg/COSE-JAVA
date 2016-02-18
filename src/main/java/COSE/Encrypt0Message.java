/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author jimsch
 */
public class Encrypt0Message extends EncryptCommon {
    public Encrypt0Message() {
        this(true);
    }
    
    public Encrypt0Message(boolean emitTag) {
        context = "Encrypted";
        messageTag = 993;
        this.emitTag = emitTag;
    }
    
    public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 3) throw new CoseException("Invalid Encrypt0 structure");
        
        if (obj.get(0).getType() == CBORType.ByteString) {
            if (obj.get(0).GetByteString().length == 0) objProtected = CBORObject.NewMap();
            else objProtected = CBORObject.DecodeFromBytes(obj.get(0).GetByteString());
        }
        else throw new CoseException("Invalid Encrypt0 structure");
        
        if(obj.get(1).getType() == CBORType.Map) objUnprotected = obj.get(1);
        else throw new CoseException("Invalid Encrypt0 structure");
        
        if (obj.get(2).getType() == CBORType.ByteString) rgbEncrypt = obj.get(2).GetByteString();
        else throw new CoseException("Invalid Enrypt0 structure");
    }
    
    protected CBORObject EncodeCBORObject() throws CoseException {
        if (rgbEncrypt == null) throw new CoseException("Encrypt function not called");
        
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        
        obj.Add(rgbEncrypt);
        
        return obj;
    }
    
    @Override
    public byte[] Decrypt(byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        return super.Decrypt(rgbKey);
    }
    
    public void Encrypt(byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        super.encryptWithKey(rgbKey);
    }
}
