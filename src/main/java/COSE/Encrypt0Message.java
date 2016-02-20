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

    /**
     * Create a Encrypt0Message object.  This object corresponds to the encrypt
   message format in COSE.  The leading CBOR tag will be emitted.
   The message content will be emitted.
     */
    public Encrypt0Message() {
        this(true, true);
    }
    
    /**
     * Create a Encrypt0Message object.  This object corresponds to the encrypt
   message format in COSE.
     * 
     * @param emitTag is the leading CBOR tag emitted
     * @param emitContent is the content emitted
     */
    public Encrypt0Message(boolean emitTag, boolean emitContent) {
        context = "Encrypted";
        messageTag = MessageTag.Encrypt0;
        this.emitTag = emitTag;
        this.emitContent = emitContent;
    }
    
    @Override
    public void DecodeFromCBORObject(CBORObject obj) throws CoseException {
        if (obj.size() != 3) throw new CoseException("Invalid Encrypt0 structure");
        
        if (obj.get(0).getType() == CBORType.ByteString) {
            if (obj.get(0).GetByteString().length == 0) {
                rgbProtected = new byte[0];
                objProtected = CBORObject.NewMap();
            }
            else {
                rgbProtected = obj.get(0).GetByteString();
                objProtected = CBORObject.DecodeFromBytes(rgbProtected);
            }
            
        }
        else throw new CoseException("Invalid Encrypt0 structure");
        
        if(obj.get(1).getType() == CBORType.Map) objUnprotected = obj.get(1);
        else throw new CoseException("Invalid Encrypt0 structure");
        
        if (obj.get(2).getType() == CBORType.ByteString) rgbEncrypt = obj.get(2).GetByteString();
        else throw new CoseException("Invalid Enrypt0 structure");
    }
    
    /**
     * Internal function used to construct the CBORObject 
     * @return the constructed CBORObject
     * @throws CoseException if the content has not yet been encrypted
     */
    @Override
    protected CBORObject EncodeCBORObject() throws CoseException {
        if (rgbEncrypt == null) throw new CoseException("Encrypt function not called");
        
        CBORObject obj = CBORObject.NewArray();
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        
        obj.Add(objUnprotected);
        
        if (emitContent) obj.Add(rgbEncrypt);
        else obj.Add(null);
        
        return obj;
    }
    
    /**
     * Decrypt the message using the passed in key.
     * 
     * @param rgbKey key for decryption
     * @return the decrypted content
     * @throws CoseException 
     * @throws InvalidCipherTextException when the decryption does not authenticate
     */
    public byte[] decrypt(byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        return super.decryptWithKey(rgbKey);
    }
    
    /**
     * Encrypt the message using the passed in key.
     * 
     * @param rgbKey key used for encryption
     * @throws CoseException
     * @throws IllegalStateException
     * @throws InvalidCipherTextException
     */
    public void encrypt(byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        super.encryptWithKey(rgbKey);
    }
}
