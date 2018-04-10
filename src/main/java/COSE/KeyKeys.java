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
    Algorithm(3),
    KeyId(2),
    Key_Ops(4),
    Base_IV(5),
    Octet_K(-1),
    EC2_Curve(-1),
    EC2_X(-2),
    EC2_Y(-3),
    EC2_D(-4),
    OKP_Curve(-1),
    OKP_X(-2),
    OKP_D(-4),
            ;
    
    private final CBORObject value;
    
    public final static CBORObject KeyType_OKP = CBORObject.FromObject(1);
    public final static CBORObject KeyType_EC2 = CBORObject.FromObject(2);
    public final static CBORObject KeyType_Octet =  CBORObject.FromObject(4);
    
    public final static CBORObject EC2_P256 = CBORObject.FromObject(1);
    public final static CBORObject EC2_P384 = CBORObject.FromObject(2);
    public final static CBORObject EC2_P521 = CBORObject.FromObject(3);
    
    public final static CBORObject OKP_X25519 = CBORObject.FromObject(4);
    public final static CBORObject OKP_X448 = CBORObject.FromObject(5);
    public final static CBORObject OKP_Ed25519 = CBORObject.FromObject(6);
    public final static CBORObject OKP_Ed448 = CBORObject.FromObject(7);
    
    KeyKeys(int val) {
        this.value = CBORObject.FromObject(val);
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
    
}
