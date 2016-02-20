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
public enum HeaderKeys {
    Algorithm(1),
    CONTENT_TYPE(3),
    KID(2),
    IV(5),
    PARTIAL_IV(6),
    ECDH_EPK(-1),
    ECDH_SPK(-2),
    ECDH_SKID(-3);
    
    private CBORObject value;
    
    HeaderKeys(int val) {
        this.value = CBORObject.FromObject(val);
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
}
