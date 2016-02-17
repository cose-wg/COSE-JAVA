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
    public static final int ProtectedAttributes = 1;
    public static final int UnprotectedAttributes = 2;
    public static final int DontSendAttributes = 4;
    
    public void addAttribute(CBORObject label, CBORObject value, int where) {
        RemoveAttribute(label);
        switch (where) {
            case 1:
                objProtected.Add(label, value);
                break;
                
            case 2:
                objUnprotected.Add(label, value);
                break;
                
            case 4:
                objDontSend.Add(label, value);
                break;
        }
    }
    
    public void addAttribute(HeaderKeys label, CBORObject value, int where) {
        addAttribute(label.AsCBOR(), value, where);
    }
    
    public void AddProtected(CBORObject label, CBORObject value) {
        RemoveAttribute(label);
        objProtected.Add(label, value);
    }
    
    public void AddProtected(HeaderKeys label, CBORObject value) {
        AddProtected(label.AsCBOR(), value);
    }
    
    public void AddProtected(HeaderKeys label, byte[] value) {
        AddProtected(label, CBORObject.FromObject(value));
    }

    public void AddUnprotected(CBORObject label, CBORObject value) {
        RemoveAttribute(label);
        objUnprotected.Add(label, value);
    }
    
    public void AddUnprotected(HeaderKeys label, CBORObject value) {
        AddUnprotected(label.AsCBOR(), value);
    }
    
    public void AddUnprotected(HeaderKeys label, byte[] value) {
        AddUnprotected(label, CBORObject.FromObject(value));
    }

    public CBORObject FindAttribute(CBORObject label) {
        if (objProtected.ContainsKey(label)) return objProtected.get(label);
        if (objUnprotected.ContainsKey(label)) return objUnprotected.get(label);
        if (objDontSend.ContainsKey(label)) return objDontSend.get(label);
        return null;
    }
    
    public CBORObject FindAttribute(HeaderKeys key) {
        return FindAttribute(key.AsCBOR());
    }
    
    private void RemoveAttribute(CBORObject label) {
        if (objProtected.ContainsKey(label)) objProtected.Remove(label);
        if (objUnprotected.ContainsKey(label)) objUnprotected.Remove(label);
        if (objDontSend.ContainsKey(label)) objDontSend.Remove(label);
    }
}
