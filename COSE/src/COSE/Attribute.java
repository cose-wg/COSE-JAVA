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
public class Attribute {
    protected CBORObject objProtected = CBORObject.NewMap();
    protected CBORObject objUnprotected = CBORObject.NewMap();
    protected CBORObject objDontSend = CBORObject.NewMap();
    
    public CBORObject FindAttribute(CBORObject label) {
        if (objProtected.ContainsKey(label)) return objProtected.get(label);
        if (objUnprotected.ContainsKey(label)) return objUnprotected.get(label);
        if (objDontSend.ContainsKey(label)) return objDontSend.get(label);
        return null;
    }
}
