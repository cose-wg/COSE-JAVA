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
    AES_GCM_128(1, 128, 128),
    AES_GCM_192(2, 192, 128),
    AES_GCM_256(3, 256, 128),
    HMAC_SHA_256_64(4, 256, 64),
    HMAC_SHA_256(5, 256, 256),
    HMAC_SHA_384(6, 384, 384),
    HMAC_SHA_512(7, 512, 512),
    AES_CCM_16_64_128(10, 128, 64),
    AES_CCM_16_64_256(11, 256, 64),
    AES_CCM_64_64_128(12, 128, 64),
    AES_CCM_64_64_256(13, 256, 64),
    AES_CBC_MAC_128_64(14, 128, 64),
    AES_CBC_MAC_256_64(15, 256, 64),
    AES_CBC_MAC_128_128(25, 128, 128),
    AES_CBC_MAC_256_128(26, 256, 128),
    AES_CCM_16_128_128(30, 128, 128),
    AES_CCM_16_128_256(31, 256, 128),
    AES_CCM_64_128_128(32, 128, 128),
    AES_CCM_64_128_256(33, 256, 128),
    
    AES_KW_128(-3, 128, 64),
    AES_KW_192(-4, 192, 64),
    AES_KW_256(-5, 256, 64),
    Direct(-6, 0, 0);
 
    private final CBORObject value;
    private final int cbitKey;
    private final int cbitTag;
    
    AlgorithmID(int value, int cbitKey, int cbitTag) {
        this.value = CBORObject.FromObject(value);
        this.cbitKey = cbitKey;
        this.cbitTag = cbitTag;
    }    
    
    public static AlgorithmID FromCBOR(CBORObject obj) throws CoseException {
        if (obj == null) throw new CoseException("No Algorithm Specified");
        for (AlgorithmID alg : AlgorithmID.values()) {
            if (obj.equals(alg.value)) return alg;
        }
        throw new CoseException("Unknown Algorithm Specified");
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
    
    public int getKeySize() {
        return cbitKey;
    }
    
    public int getTagSize() {
        return cbitTag;
    }
}
