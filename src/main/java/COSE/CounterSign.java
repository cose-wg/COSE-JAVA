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
public class CounterSign extends Signer {
    
    public void DecodeFromBytes(byte[] rgb) throws CoseException
    {
        CBORObject obj = CBORObject.DecodeFromBytes(rgb);
        
        DecodeFromCBORObject(obj);
    }
}
