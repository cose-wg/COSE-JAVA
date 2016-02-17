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

    protected void Create(byte[] rgbKey) throws CoseException {
        CBORObject algX = FindAttribute(CBORObject.FromObject(1)); //HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
        
        switch (alg) {
            case HMAC_SHA_256_64:
            case HMAC_SHA_256:
            case HMAC_SHA_384:
            case HMAC_SHA_512:
                rgbTag = HMAC(alg, rgbKey);
                break;
                
            default:
                throw new CoseException("Unsupported MAC Algorithm");
        }
    }
    
    protected boolean Validate(byte[] rgbKey) throws CoseException {
        boolean f;
        int i;
        byte[] rgbTest;
        
        CBORObject algX = FindAttribute(CBORObject.FromObject(1)); //HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
        
        switch (alg) {
            case HMAC_SHA_256_64:
            case HMAC_SHA_256:
            case HMAC_SHA_384:
            case HMAC_SHA_512:
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
    
    private byte[] HMAC(AlgorithmID alg, byte[] rgbKey) throws CoseException {
        Digest digest;
        
        switch (alg) {
            case HMAC_SHA_256_64:
                digest = new SHA256Digest();
                break;
                
            case HMAC_SHA_256:
                digest = new SHA256Digest();
                break;
                
            case HMAC_SHA_384:
                digest = new SHA384Digest();
                break;
                
            case HMAC_SHA_512:
                digest = new SHA512Digest();
                break;
                
            default:
                throw new CoseException("Internal Error");
        }
        
        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Key is incorrect size");
        
        HMac hmac = new HMac(digest);
        KeyParameter key = new KeyParameter(rgbKey);
        byte[] toDigest = BuildContentBytes();

        byte[] resBuf = new byte[hmac.getMacSize()];

        hmac.init(key);
        hmac.update(toDigest, 0, toDigest.length);
        hmac.doFinal(resBuf, 0);

        byte[] returnVal = new byte[alg.getTagSize()/8];
        System.arraycopy(resBuf, 0, returnVal, 0, alg.getTagSize()/8);
        return returnVal;
    }
}
