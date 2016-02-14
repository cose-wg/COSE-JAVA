/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.security.SecureRandom;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.gcm.BasicGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author jimsch
 */
public abstract class EncryptCommon extends Message {
    protected String context;
    protected byte[] rgbEncrypt;
    protected byte[] rgbContent;
    SecureRandom random = new SecureRandom();
    
    protected byte[] Decrypt(byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        CBORObject algX = FindAttribute(HeaderKeys.Algorithm.AsCBOR());
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
        int cbitCEK;
        
        switch (alg) {
            case AES_GCM_128:
                cbitCEK = 128;
                break;
                
            case AES_GCM_192:
                cbitCEK = 192;
                break;
                
            case AES_GCM_256:
                cbitCEK = 256;
                break;
                
            default:
                throw new CoseException("Unknown Encryption Algorithm");
        }
        
        if (rgbKey.length != cbitCEK/8) throw new CoseException("Incorrect Key Size");
        
        switch (alg) {
            case AES_GCM_128:
            case AES_GCM_192:
            case AES_GCM_256:
                AES_Decrypt(alg, rgbKey);
                break;
        }
        
        return rgbContent;
    }
    
    protected void Encrypt(byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        CBORObject algX = FindAttribute(HeaderKeys.Algorithm.AsCBOR());
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
        int cbitCEK;
        
        switch (alg) {
            case AES_GCM_128:
                cbitCEK = 128;
                break;
                
            case AES_GCM_192:
                cbitCEK = 192;
                break;
                
            case AES_GCM_256:
                cbitCEK = 256;
                break;
                
            default:
                throw new CoseException("Unknown Encryption Algorithm");
        }
        
        if (rgbKey.length != cbitCEK/8) throw new CoseException("Incorrect Key Size");

        switch (alg) {
            case AES_GCM_128:
            case AES_GCM_192:
            case AES_GCM_256:
                AES_Encrypt(alg, rgbKey);
                break;
        }
    }
    
    private void AES_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESFastEngine(), new BasicGCMMultiplier());
        KeyParameter contentKey = new KeyParameter(rgbKey);
        
        CBORObject cn = FindAttribute(HeaderKeys.IV);
        if (cn == null) throw new CoseException("Missing IV during decryption");
        if (cn.getType() != CBORType.ByteString) throw new CoseException("IV is incorrectly formed");
        if (cn.GetByteString().length != 96/8) throw new CoseException("IV size is incorrect");
        
        AEADParameters parameters = new AEADParameters(contentKey, 128, cn.GetByteString(), getAADBytes());
        
        cipher.init(false, parameters);
        byte[] C = new byte[cipher.getOutputSize(rgbEncrypt.length)];
        int length = cipher.processBytes(rgbEncrypt, 0, rgbEncrypt.length, C, 0);
        length += cipher.doFinal(C, length);
        
        rgbContent = C;
    }

    private void AES_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESFastEngine(), new BasicGCMMultiplier());
        KeyParameter contentKey = new KeyParameter(rgbKey);
        
        CBORObject cn = FindAttribute(HeaderKeys.IV);
        byte[] IV;
        
        if (cn == null) {
            IV = new byte[96/8];
            random.nextBytes(IV);
            AddUnprotected(HeaderKeys.IV, CBORObject.FromObject(IV));
        }
        else {
            if (cn.getType() != CBORType.ByteString) throw new CoseException("IV is incorrectly formed");
            if (cn.GetByteString().length != 96/8) throw new CoseException("IV size is incorrect");
            IV = cn.GetByteString();
        }
        
        AEADParameters parameters = new AEADParameters(contentKey, 128, IV, getAADBytes());
        
        cipher.init(true, parameters);
        byte[] C = new byte[cipher.getOutputSize(rgbContent.length)];
        int length = cipher.processBytes(rgbContent, 0, rgbContent.length, C, 0);
        length += cipher.doFinal(C, length);
        
        rgbEncrypt = C;
    }
    
    private byte[] getAADBytes() {
        CBORObject obj = CBORObject.NewArray();
        
        obj.Add(context);
        if (objProtected.size() == 0) obj.Add(CBORObject.FromObject(new byte[0]));
        else obj.Add(objProtected.EncodeToBytes());
        obj.Add(CBORObject.FromObject(externalData));
        return obj.EncodeToBytes();
    }
}
