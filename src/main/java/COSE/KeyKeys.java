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
public enum KeyKeys {
    KeyType(1),
    Octet_K(-1);
    
    private final CBORObject value;
    
    public final static CBORObject KeyType_Octet =  CBORObject.FromObject(4);
    
    KeyKeys(int val) {
        this.value = CBORObject.FromObject(val);
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
    
}
