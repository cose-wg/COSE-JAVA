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
public class SignMessage extends Message {

    @Override
    protected void DecodeFromCBORObject(CBORObject messageObject) throws CoseException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected CBORObject EncodeCBORObject() throws CoseException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    public void AddSigner(Signer signedBy) {
        
    }
    
    public Signer getSigner(int iSigner) {
        return null;
    }
    
    public void sign() {
    }
    
    public boolean validate(Signer signerToUse) {
        return false;
    }
}
