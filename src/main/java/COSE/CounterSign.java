/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;

/**
 *
 * @author jimsch
 */
public class CounterSign extends Signer {
    
    public CounterSign() {
        contextString = "CounterSignature";
    }
    
    public CounterSign(byte[] rgb) throws CoseException {
        contextString = "CounterSignature";
        DecodeFromBytes(rgb);
    }
    
    public CounterSign(CBORObject cbor) throws CoseException {
        DecodeFromCBORObject(cbor);
        contextString = "CounterSignature";
    }
    
    public void DecodeFromBytes(byte[] rgb) throws CoseException
    {
        CBORObject obj = CBORObject.DecodeFromBytes(rgb);
        
        DecodeFromCBORObject(obj);
    }
    
    public byte[] EncodeToBytes() throws CoseException {
        return EncodeToCBORObject().EncodeToBytes();
    }
    
    public void Sign(Message message) throws CoseException {
        byte[] rgbBodyProtect;
        if (message.objProtected.size() > 0) rgbBodyProtect = message.objProtected.EncodeToBytes();
        else rgbBodyProtect = new byte[0];
        
        sign(rgbBodyProtect, message.rgbContent);        
    }
    
    public boolean Validate(Message message) throws CoseException {
        byte[] rgbBodyProtect;
        if (message.objProtected.size() > 0) rgbBodyProtect = message.objProtected.EncodeToBytes();
        else rgbBodyProtect = new byte[0];
        
        return validate(rgbBodyProtect, message.rgbContent);
    }
    
    private Message m_msgToSign;
    private Signer m_signerToSign;
    
    public void setObject(Message msg)
    {
        m_msgToSign = msg;
    }
    
    public void setObject(Signer signer)
    {
        m_signerToSign = signer;
    }

}
