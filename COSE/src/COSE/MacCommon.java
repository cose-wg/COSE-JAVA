/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author jimsch
 */

public abstract class MacCommon extends Message {
    protected byte[] rgbContent;
    protected byte[] rgbTag;
    protected List<Recipient> recipientList = new ArrayList<Recipient>();
    protected String strContext;
    
    protected MacCommon() {
        super();
    }
    
    protected boolean Validate(byte[] rgbKey) throws CoseException {
        boolean f;
        int i;
        byte[] rgbTest;
        
        CBORObject alg = FindAttribute(CBORObject.FromObject(1)); //HeaderKeys.Algorithm);
        if (alg.getType() == CBORType.TextString) {
            throw new CoseException("Unsupported MAC Algorithm");
        }
        else if (alg.getType() != CBORType.Number) {
            throw new CoseException("Malformed MAC algorithm field");
        } 
        
        switch (alg.AsInt32()) {
            case 4: // HMAC_SHA_256_64
            case 5: // HMAC_SHA_256
            case 6: // HMAC_SHA_384
            case 7: // HMAC_SHA_512
                rgbTest = HMAC(alg, rgbKey);
                break;
                
            default:
                throw new CoseException("Unsupported MAC Algorithm");
        }
        
        if (rgbTest.length != rgbTag.length) return false;
        f = true;
        for (i=0; i<rgbTest.length; i++) {
            f &= (rgbTest[i] == rgbTag[i]);
        }
        return f;
    }
    
    private byte[] BuildContentBytes() {
        CBORObject obj = CBORObject.NewArray();
        
        obj.Add(strContext);
        if (objProtected.size() > 0) obj.Add(objProtected.EncodeToBytes());
        else obj.Add(CBORObject.FromObject(new byte[0]));
        if (externalData != null) obj.Add(CBORObject.FromObject(externalData));
        else obj.Add(CBORObject.FromObject(new byte[0]));
        obj.Add(rgbContent);
        
        return obj.EncodeToBytes();
    }
    
    private byte[] HMAC(CBORObject alg, byte[] rgbKey) throws CoseException {
        Digest digest;
        int cbitKey;
        int cbResult;
        
        switch (alg.AsInt32()) {
            case 4: // HMAC_SHA_256_64
                cbitKey = 256;
                cbResult = 64/8;
                digest = new SHA256Digest();
                break;
                
            case 5: // HMAC_SHA_256
                cbitKey = 256;
                cbResult = 256/8;
                digest = new SHA256Digest();
                break;
                
            case 6: // HMAC_SHA_384
                cbitKey = 384;
                cbResult =384/8;
                digest = new SHA384Digest();
                break;
                
            case 7: // HMAC_SHA_512
                cbitKey = 512;
                cbResult = 512/8;
                digest = new SHA512Digest();
                break;
                
            default:
                throw new CoseException("Internal Error");
        }
        
        if (rgbKey.length != cbitKey/8) throw new CoseException("Key is incorrect size");
        
        HMac hmac = new HMac(digest);
        KeyParameter key = new KeyParameter(rgbKey);
        byte[] toDigest = BuildContentBytes();

        byte[] resBuf = new byte[hmac.getMacSize()];

        hmac.init(key);
        hmac.update(toDigest, 0, toDigest.length);
        hmac.doFinal(resBuf, 0);

        byte[] returnVal = new byte[cbResult];
        System.arraycopy(resBuf, 0, returnVal, 0, cbResult);
        return returnVal;
    }
}
