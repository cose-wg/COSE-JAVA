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
    protected byte[] rgbProtected;
    protected byte[] externalData = new byte[0];
    public static final int ProtectedAttributes = 1;
    public static final int UnprotectedAttributes = 2;
    public static final int DontSendAttributes = 4;
    
    /**
     * Set an attribute in the COSE object.
     * 
     * @param label CBOR object which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * @param where Identifies which of the buckets to place the attribute in.
     *      ProtectedAttributes - attributes cryptographically protected
     *      UnprotectedAttributes - attributes not cryptographically protected
     *      DontSendAttributes - attributes used locally and not transmitted
     */
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
    
    /**
     * Set an attribute in the COSE object.
     * 
     * @param label HeaderKeys label which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * @param where Identifies which of the buckets to place the attribute in.
     *      ProtectedAttributes - attributes cryptographically protected
     *      UnprotectedAttributes - attributes not cryptographically protected
     *      DontSendAttributes - attributes used locally and not transmitted
     */
    public void addAttribute(HeaderKeys label, CBORObject value, int where) {
        addAttribute(label.AsCBOR(), value, where);
    }
    
    /**
     * Set an attribute in the COSE object.
     * 
     * @param label HeaderKeys label which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * @param where Identifies which of the buckets to place the attribute in.
     *      ProtectedAttributes - attributes cryptographically protected
     *      UnprotectedAttributes - attributes not cryptographically protected
     *      DontSendAttributes - attributes used locally and not transmitted
     */
    public void addAttribute(HeaderKeys label, byte[] value, int where) {
        addAttribute(label.AsCBOR(), CBORObject.FromObject(value), where);
    }

    /**
     * Set an attribute in the protect bucket of the COSE object
     * 
     * @param label CBOR object which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * 
     * @deprecated use {@link #addAttribute}
     */
    @Deprecated
    public void AddProtected(CBORObject label, CBORObject value) {
        RemoveAttribute(label);
        objProtected.Add(label, value);
    }
    
    /**
     * Set an attribute in the protect bucket of the COSE object
     * 
     * @param label HeaderKeys label which identifies the attribute in the map
     * @param value CBOR object which contains the value of the attribute
     * 
     * @deprecated use {@link #addAttribute}
     */
    @Deprecated
    public void AddProtected(HeaderKeys label, CBORObject value) {
        AddProtected(label.AsCBOR(), value);
    }
    
    /**
     * Set an attribute in the protect bucket of the COSE object
     * 
     * @param label CBOR object which identifies the attribute in the map
     * @param value byte array of value
     * 
     * @deprecated use {@link #addAttribute(HeaderKeys, byte[], int)}
     *      with ProtectedAttributes
     */
    @Deprecated
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

    /**
     *  Locate an attribute in one of the attribute buckets  The buckets are
     *  searched in the order protected, unprotected, unsent.
     * 
     * @param label - Label of the value to be searched for
     * @return - CBORObject with the value if found; otherwise null
     */
    public CBORObject findAttribute(CBORObject label) {
        if (objProtected.ContainsKey(label)) return objProtected.get(label);
        if (objUnprotected.ContainsKey(label)) return objUnprotected.get(label);
        if (objDontSend.ContainsKey(label)) return objDontSend.get(label);
        return null;
    }
    
    /**
     *  Locate an attribute in one of the attribute buckets  The buckets are
     *  searched in the order protected, unprotected, unsent.
     * 
     * @param key - HeaderKey enumeration value to search for
     * @return - CBORObject with the value if found; otherwise null
     */
    public CBORObject findAttribute(HeaderKeys key) {
        return Attribute.this.findAttribute(key.AsCBOR());
    }
    
    private void RemoveAttribute(CBORObject label) {
        if (objProtected.ContainsKey(label)) objProtected.Remove(label);
        if (objUnprotected.ContainsKey(label)) objUnprotected.Remove(label);
        if (objDontSend.ContainsKey(label)) objDontSend.Remove(label);
    }
    
    /**
     * Set the optional external data field to be authenticated
     * 
     * @param rgbData - data to be authenticated
     */
    public void setExternal(byte[] rgbData) {
        if (rgbData == null) rgbData = new byte[0];
        externalData = rgbData;
    }                
}
