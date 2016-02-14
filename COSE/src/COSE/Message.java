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
public class Message extends Attribute {
    protected byte[] externalData = null;
  
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
        
        switch (defaultTag) {
            case 0: // Unknown
                throw new CoseException("Message was not tagged and no default tagging option given");
                
            case 994: {
                MACMessage mac = new MACMessage();
                mac.DecodeFromCBORObject(messageObject);
                return mac;
            }
            
            case 996: {
                MAC0Message mac = new MAC0Message();
                mac.DecodeFromCBORObject(messageObject);
                return mac;
            }
                
            default:
                throw new CoseException("Message is not recognized as a COSE security Object");
        }
    }
    
    public void SetExternal(byte[] rgbData) {
        externalData = rgbData;
    }            
}
