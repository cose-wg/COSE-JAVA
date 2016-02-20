/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.nio.charset.StandardCharsets;

/**
 *
 * @author jimsch
 */
public abstract class Message extends Attribute {
    protected byte[] externalData = new byte[0];
    protected boolean emitTag = true;
    protected int messageTag;
    protected byte[] rgbContent;
  
    /**
     * Decode a 
     * @param rgbData
     * @param defaultTag
     * @return 
     */
    public static Message DecodeFromBytes(byte[] rgbData, int defaultTag) throws CoseException {
        CBORObject messageObject = CBORObject.DecodeFromBytes(rgbData);
        
        if (messageObject.getType() != CBORType.Array)  throw new CoseException("Message is not a COSE security Message");
        
        if (messageObject.isTagged()) {
            if (messageObject.GetTags().length != 1) throw new CoseException("Malformed message - too many tags");
            
            if (defaultTag == 0) {
                defaultTag = messageObject.getOutermostTag().intValue();
            }
            else if (defaultTag != messageObject.getOutermostTag().intValue()) {
                throw new CoseException("Passed in tag does not match actual tag");
            }
        }
        
        Message msg;
        
        switch (defaultTag) {
            case 0: // Unknown
                throw new CoseException("Message was not tagged and no default tagging option given");
                
            case 992:
                msg = new EncryptMessage();
                break;
                        
            case 993: 
                msg = new Encrypt0Message();
                break;

            case 994: 
                msg = new MACMessage();
                break;
            
            case 996: 
                msg = new MAC0Message();
                break;
                
            case 997:
                msg = new Sign1Message();
                break;
                
            default:
                throw new CoseException("Message is not recognized as a COSE security Object");
        }
    
        msg.DecodeFromCBORObject(messageObject);
        return msg;
        
    }
    
    public byte[] EncodeToBytes() throws CoseException {
        return EncodeToCBORObject().EncodeToBytes();
    }

    protected abstract void DecodeFromCBORObject(CBORObject messageObject) throws CoseException;
    protected abstract CBORObject EncodeCBORObject() throws CoseException;
    public CBORObject EncodeToCBORObject() throws CoseException {
        CBORObject obj;
        
        obj = EncodeCBORObject();
        
        if (emitTag) {
            obj = CBORObject.FromObjectAndTag(obj, messageTag);
        }
        
        return obj;
    }

    public byte[] GetContent() {
        return rgbContent;
    }
    
    public void SetContent(byte[] rgbData) {
        rgbContent = rgbData;
    }
    
    public void SetContent(String strData) {
        rgbContent = strData.getBytes(StandardCharsets.UTF_8);
    }

    public void SetExternal(byte[] rgbData) {
        externalData = rgbData;
    }            
}
