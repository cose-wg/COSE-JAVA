/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author jimsch
 */

public abstract class MacCommon extends Message {
    protected byte[] rgbTag;
    protected String strContext;
    protected SecureRandom random = new SecureRandom();
    
    protected MacCommon() {
        super();
    }

    protected void CreateWithKey(byte[] rgbKey) throws CoseException {
        CBORObject algX = findAttribute(CBORObject.FromObject(1)); //HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);

        if (rgbContent == null) throw new CoseException("No Content Specified");
        
        switch (alg) {
            case HMAC_SHA_256_64:
            case HMAC_SHA_256:
            case HMAC_SHA_384:
            case HMAC_SHA_512:
                rgbTag = HMAC(alg, rgbKey);
                break;
                
            case AES_CBC_MAC_128_64:
            case AES_CBC_MAC_256_64:
                rgbTag = AES_CBC_MAC(alg, rgbKey, 8);
                break;

            case AES_CBC_MAC_128_128:
            case AES_CBC_MAC_256_128:
                rgbTag = AES_CBC_MAC(alg, rgbKey, 16);
                break;

            default:
                throw new CoseException("Unsupported MAC Algorithm");
        }
    }
    
    protected boolean Validate(byte[] rgbKey) throws CoseException {
        boolean f;
        int i;
        byte[] rgbTest;
        
        CBORObject algX = findAttribute(CBORObject.FromObject(1)); //HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
        
        switch (alg) {
            case HMAC_SHA_256_64:
            case HMAC_SHA_256:
            case HMAC_SHA_384:
            case HMAC_SHA_512:
                rgbTest = HMAC(alg, rgbKey);
                break;
                
            case AES_CBC_MAC_128_64:
            case AES_CBC_MAC_256_64:
                rgbTest = AES_CBC_MAC(alg, rgbKey, 8);
                break;

            case AES_CBC_MAC_128_128:
            case AES_CBC_MAC_256_128:
                rgbTest = AES_CBC_MAC(alg, rgbKey, 16);
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
        
        if (rgbProtected == null) {
            if (objProtected.size() == 0) rgbProtected = new byte[0]; 
            else rgbProtected = objProtected.EncodeToBytes();
        }
        
        obj.Add(strContext);
        obj.Add(rgbProtected);
        if (externalData != null) obj.Add(CBORObject.FromObject(externalData));
        else obj.Add(CBORObject.FromObject(new byte[0]));
        obj.Add(rgbContent);
        
        return obj.EncodeToBytes();
    }
    
    protected byte[] AES_CBC_MAC(AlgorithmID alg, byte[] rgbKey, int tagLen) throws CoseException
    {
        if (rgbKey.length != alg.getKeySize() / 8) throw new CoseException("Key is incorrectly sized");

        //  The requirements from spec
        //  IV is 128 bits of zeros
        //  key sizes are 128, 192 and 256 bits
        //  Authentication tag sizes are 64 and 128 bits
        byte[] IV = new byte[128 / 8];

        try {
            Cipher cbcmac = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cbcmac.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rgbKey, "AES"),
                        new IvParameterSpec(IV));
            byte[] val = BuildContentBytes();
            val = cbcmac.doFinal(val);
            int blocksize = cbcmac.getBlockSize();
            val = Arrays.copyOfRange(val, val.length - blocksize, val.length - (blocksize - tagLen));
            return val;
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Mac failure", ex);
        }
    }
    
    private byte[] HMAC(AlgorithmID alg, byte[] rgbKey) throws CoseException {
        String          algStr;
        
        switch (alg) {
            case HMAC_SHA_256_64:
            case HMAC_SHA_256:
                algStr = "HmacSHA256";
                break;
                
            case HMAC_SHA_384:
                algStr = "HmacSHA384";
                break;
                
            case HMAC_SHA_512:
                algStr = "HmacSHA512";
                break;
                
            default:
                throw new CoseException("Internal Error");
        }
        
        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Key is incorrect size");
        
        try {
            Mac hmac = Mac.getInstance(algStr);
            hmac.init(new SecretKeySpec(rgbKey, algStr));
            byte[] val = BuildContentBytes();
            val = hmac.doFinal(val);
            return val;
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Mac failure", ex);
        }
    }
}
