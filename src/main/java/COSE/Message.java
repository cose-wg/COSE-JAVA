/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 *
 * @author jimsch
 */
public abstract class Message extends Attribute {
    protected byte[] externalData = new byte[0];
  
    /**
     * Decode a 
     * @param rgbData
     * @param defaultTag
     * @return 
     */
    public static Message DecodeFromBytes(byte[] rgbData, int defaultTag) throws CoseException {
        CBORObject messageObject = CBORObject.DecodeFromBytes(rgbData);
        
        if (messageObject.getType() != CBORType.Array)  throw new CoseException("Message isnot a COSE security Message");
        
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
                
            case 993: 
                msg = new Encrypt0Message();
                break;
            case 994: 
                msg = new MACMessage();
                break;
            
            case 996: 
                msg = new MAC0Message();
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

    public abstract void DecodeFromCBORObject(CBORObject messageObject) throws CoseException;
    public abstract CBORObject EncodeToCBORObject() throws CoseException;

    public void SetExternal(byte[] rgbData) {
        externalData = rgbData;
    }            
}
