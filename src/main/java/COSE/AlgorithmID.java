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
public enum AlgorithmID {
    AES_GCM_128(1),
    AES_GCM_192(2),
    AES_GCM_256(3),
    HMAC_SHA_256_64(4),
    HMAC_SHA_256(5),
    HMAC_SHA_384(6),
    HMAC_SHA_512(7);
 
    private CBORObject value;
    
    AlgorithmID(int value) {
        this.value = CBORObject.FromObject(value);
    }    
    public static AlgorithmID FromCBOR(CBORObject obj) {
        for (AlgorithmID alg : AlgorithmID.values()) {
            if (obj.equals(alg.value)) return alg;
        }
        return null;
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
}
