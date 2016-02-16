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
import org.bouncycastle.crypto.modes.CCMBlockCipher;
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
                
 
        switch (alg) {
            case AES_GCM_128:
            case AES_GCM_192:
            case AES_GCM_256:
                AES_GCM_Decrypt(alg, rgbKey);
                break;
                
            case AES_CCM_16_64_128:
            case AES_CCM_16_64_256:
            case AES_CCM_64_64_128:
            case AES_CCM_64_64_256:
            case AES_CCM_16_128_128:
            case AES_CCM_16_128_256:
            case AES_CCM_64_128_128:
            case AES_CCM_64_128_256:
                AES_CCM_Decrypt(alg, rgbKey);
                break;
                
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        return rgbContent;
    }
    
    protected void Encrypt(byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        CBORObject algX = FindAttribute(HeaderKeys.Algorithm.AsCBOR());
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
                
        if (rgbContent == null) throw new CoseException("No Content Specified");

        switch (alg) {
            case AES_GCM_128:
            case AES_GCM_192:
            case AES_GCM_256:
                if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Incorrect Key Size");
                AES_GCM_Encrypt(alg, rgbKey);
                break;

            case AES_CCM_16_64_128:
            case AES_CCM_16_64_256:
            case AES_CCM_64_64_128:
            case AES_CCM_64_64_256:
            case AES_CCM_16_128_128:
            case AES_CCM_16_128_256:
            case AES_CCM_64_128_128:
            case AES_CCM_64_128_256:
                if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Incorrect Key Size");
                AES_CCM_Encrypt(alg, rgbKey);
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
    }
    
    public byte[] GetContent() {
        return rgbContent;
    }
    
    public void SetContent(byte[] rgbData) {
        rgbContent = rgbData;
    }

    private void AES_CCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException
    {
        CCMBlockCipher cipher = new CCMBlockCipher(new AESFastEngine());
        KeyParameter ContentKey;
        int cbIV = 0;

        switch (alg) {
        case AES_CCM_16_64_128:
        case AES_CCM_16_64_256:
        case AES_CCM_16_128_128:
        case AES_CCM_16_128_256:
            cbIV = 15 - 2;
            break;

        case AES_CCM_64_64_128:
        case AES_CCM_64_64_256:
        case AES_CCM_64_128_256:
        case AES_CCM_64_128_128:
            cbIV = 15 - 8;
            break;
        }

        //  The requirements from JWA

        CBORObject cn = FindAttribute(HeaderKeys.IV);
        if (cn == null) throw new CoseException("Missing IV during decryption");
        if (cn.getType() != CBORType.ByteString) throw new CoseException("IV is incorrectly formed");
        if (cn.GetByteString().length != cbIV) throw new CoseException("IV size is incorrect");

        byte[] IV = cn.GetByteString();

        
        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Missing IV during decryption");
        ContentKey = new KeyParameter(rgbKey);

        //  Build the object to be hashed

        AEADParameters parameters = new AEADParameters(ContentKey, alg.getTagSize(), IV, getAADBytes());

        cipher.init(false, parameters);
        byte[] C = new byte[cipher.getOutputSize(rgbEncrypt.length)];
        int len = cipher.processBytes(rgbEncrypt, 0, rgbEncrypt.length, C, 0);
        len += cipher.doFinal(C, len);

        rgbContent = C;
    }
    
 
    private byte[] AES_CCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException
    {
        CCMBlockCipher cipher = new CCMBlockCipher(new AESFastEngine());
        KeyParameter ContentKey;
        int cbIV;

        switch (alg) {
        case AES_CCM_16_64_128:
        case AES_CCM_16_64_256:
        case AES_CCM_16_128_128:
        case AES_CCM_16_128_256:
            cbIV = 15 - 2;
            break;

        case AES_CCM_64_64_128:
        case AES_CCM_64_64_256:
        case AES_CCM_64_128_256:
        case AES_CCM_64_128_128:
            cbIV = 15 - 8;
            break;

        default:
            throw new CoseException("Unsupported algorithm: " + alg);
        }

        //  The requirements from JWA

        byte[] IV = new byte[cbIV];
        CBORObject cbor = FindAttribute(HeaderKeys.IV);
        if (cbor != null) {
            if (cbor.getType() != CBORType.ByteString) throw new CoseException("IV is incorreclty formed.");
            if (cbor.GetByteString().length > cbIV) throw new CoseException("IV is too long.");
            IV = cbor.GetByteString();
        }
        else {
            random.nextBytes(IV);
            AddUnprotected(HeaderKeys.IV, CBORObject.FromObject(IV));
        }

        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Key Size is incorrect");
        ContentKey = new KeyParameter(rgbKey);

        //  Build the object to be hashed

        AEADParameters parameters = new AEADParameters(ContentKey, alg.getTagSize(), IV, getAADBytes());

        cipher.init(true, parameters);

        byte[] C = new byte[cipher.getOutputSize(rgbContent.length)];
        int len = cipher.processBytes(rgbContent, 0, rgbContent.length, C, 0);
        len += cipher.doFinal(C, len);

        return C;
    }

    private void AES_GCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESFastEngine(), new BasicGCMMultiplier());
        
        CBORObject cn = FindAttribute(HeaderKeys.IV);
        if (cn == null) throw new CoseException("Missing IV during decryption");
        if (cn.getType() != CBORType.ByteString) throw new CoseException("IV is incorrectly formed");
        if (cn.GetByteString().length != 96/8) throw new CoseException("IV size is incorrect");
        
        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Missing IV during decryption");
        KeyParameter contentKey = new KeyParameter(rgbKey);
        AEADParameters parameters = new AEADParameters(contentKey, 128, cn.GetByteString(), getAADBytes());
        
        cipher.init(false, parameters);
        byte[] C = new byte[cipher.getOutputSize(rgbEncrypt.length)];
        int length = cipher.processBytes(rgbEncrypt, 0, rgbEncrypt.length, C, 0);
        length += cipher.doFinal(C, length);
        
        rgbContent = C;
    }

    private void AES_GCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESFastEngine(), new BasicGCMMultiplier());

        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Key Size is incorrect");
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
