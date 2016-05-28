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
    protected boolean emitTag = true;
    protected boolean emitContent = true;
    protected MessageTag messageTag;
    protected byte[] rgbContent;
  
    /**
     * Decode a COSE message object.  This function assumes that the message
     * has a leading CBOR tag to identify the message type.  If this is not
     * true then use {#link DecodeFromBytes(byte[], MessageTag)}.
     * 
     * @param rgbData byte stream to be decoded
     * @return the decoded message object
     * @throws CoseException on a decode failure
     */
    public static Message DecodeFromBytes(byte[] rgbData) throws CoseException {
        return DecodeFromBytes(rgbData, MessageTag.Unknown);
    }
    
    /**
     * Decode a COSE message object. Use a value of {@code MessageTag.Unknown}
     * to decode a generic structure with tagging.  Use a specific value if
     * the tagging is absent or if a known structure is passed in.
     * 
     * @param rgbData byte stream to be decoded
     * @param defaultTag assumed message type to be decoded
     * @return the decoded message object
     * @throws CoseException on a decode failure.
     */
    public static Message DecodeFromBytes(byte[] rgbData, MessageTag defaultTag) throws CoseException {
        CBORObject messageObject = CBORObject.DecodeFromBytes(rgbData);
        
        if (messageObject.getType() != CBORType.Array)  throw new CoseException("Message is not a COSE security Message");
        
        if (messageObject.isTagged()) {
            if (messageObject.GetTags().length != 1) throw new CoseException("Malformed message - too many tags");
            
            if (defaultTag == MessageTag.Unknown) {
                defaultTag = MessageTag.FromInt(messageObject.getOutermostTag().intValue());
            }
            else if (defaultTag != MessageTag.FromInt(messageObject.getOutermostTag().intValue())) {
                throw new CoseException("Passed in tag does not match actual tag");
            }
        }
        
        Message msg;
        
        switch (defaultTag) {
            case Unknown: // Unknown
                throw new CoseException("Message was not tagged and no default tagging option given");
                
            case Encrypt:
                msg = new EncryptMessage();
                break;
                        
            case Encrypt0: 
                msg = new Encrypt0Message();
                break;

            case MAC: 
                msg = new MACMessage();
                break;
            
            case MAC0: 
                msg = new MAC0Message();
                break;
                
            case Sign1:
                msg = new Sign1Message();
                break;
                
            case Sign:
                msg = new SignMessage();
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
            obj = CBORObject.FromObjectAndTag(obj, messageTag.value);
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
    

}
