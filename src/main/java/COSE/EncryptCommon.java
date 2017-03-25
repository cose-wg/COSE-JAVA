/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author jimsch
 */
public abstract class EncryptCommon extends Message {
    private final String    AES_SPEC = "AES";
    
    private final String    AES_CCM_SPEC = AES_SPEC + "/CCM/NoPadding";
    private final int       AES_CCM_16_IV_LENGTH = 13;
    private final int       AES_CCM_64_IV_LENGTH = 7;
    
    private final String    AES_GCM_SPEC = AES_SPEC + "/GCM/NoPadding";
    private final int       AES_GCM_IV_LENGTH = 96;
    
    protected String context;
    protected byte[] rgbEncrypt;
    SecureRandom random = new SecureRandom();
    
    protected byte[] decryptWithKey(byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        CBORObject algX = findAttribute(HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
                
        if (rgbEncrypt == null) throw new CoseException("No Encrypted Content Specified");
 
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
    
    void encryptWithKey(byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        CBORObject algX = findAttribute(HeaderKeys.Algorithm);
        AlgorithmID alg = AlgorithmID.FromCBOR(algX);
                
        if (rgbContent == null) throw new CoseException("No Content Specified");

        switch (alg) {
            case AES_GCM_128:
            case AES_GCM_192:
            case AES_GCM_256:
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
                AES_CCM_Encrypt(alg, rgbKey);
                break;

            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
    }
    
    private int getAES_CCM_IVSize(AlgorithmID algID) {
        switch (algID) {
            case AES_CCM_16_64_128:
            case AES_CCM_16_64_256:
            case AES_CCM_16_128_128:
            case AES_CCM_16_128_256:
                return AES_CCM_16_IV_LENGTH;
            case AES_CCM_64_64_128:
            case AES_CCM_64_64_256:
            case AES_CCM_64_128_256:
            case AES_CCM_64_128_128:
                return AES_CCM_64_IV_LENGTH;
        }
        return 0;
    }
    
    private void AES_CCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException
    {
        // validate key
        if (rgbKey.length != alg.getKeySize()/8) {
            throw new CoseException("Key Size is incorrect");
        }

        // obtain and validate IV
        final int ivLen = getAES_CCM_IVSize(alg);
        CBORObject  iv = findAttribute(HeaderKeys.IV);
        if (iv == null) {
            throw new CoseException("Missing IV during decryption");
        }
        if (iv.getType() != CBORType.ByteString) {
            throw new CoseException("IV is incorrectly formed");
        }
        if (iv.GetByteString().length != ivLen) {
            throw new CoseException("IV size is incorrect");
        }
        
        try {
            Cipher      cipher = Cipher.getInstance(AES_CCM_SPEC);
            cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(rgbKey, AES_SPEC),
                        new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
            cipher.updateAAD(getAADBytes());
            
            rgbContent = new byte[cipher.getOutputSize(rgbEncrypt.length)];
            ByteBuffer  input = ByteBuffer.wrap(rgbEncrypt);
            ByteBuffer  output = ByteBuffer.wrap(rgbContent);
            cipher.doFinal(input, output);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Decryption failure", ex);
        }
    }
    
 
    private void AES_CCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException
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
        CBORObject cbor = findAttribute(HeaderKeys.IV);
        if (cbor != null) {
            if (cbor.getType() != CBORType.ByteString) throw new CoseException("IV is incorreclty formed.");
            if (cbor.GetByteString().length > cbIV) throw new CoseException("IV is too long.");
            IV = cbor.GetByteString();
        }
        else {
            random.nextBytes(IV);
            addAttribute(HeaderKeys.IV, CBORObject.FromObject(IV), Attribute.UNPROTECTED);
        }

        if (rgbKey.length != alg.getKeySize()/8) throw new CoseException("Key Size is incorrect");
        ContentKey = new KeyParameter(rgbKey);

        //  Build the object to be hashed

        AEADParameters parameters = new AEADParameters(ContentKey, alg.getTagSize(), IV, getAADBytes());

        cipher.init(true, parameters);

        byte[] C = new byte[cipher.getOutputSize(rgbContent.length)];
        int len = cipher.processBytes(rgbContent, 0, rgbContent.length, C, 0);
        len += cipher.doFinal(C, len);

        rgbEncrypt = C;
    }

    private void AES_GCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, InvalidCipherTextException {
        CBORObject      iv = findAttribute(HeaderKeys.IV);

        // validate key
        if (rgbKey.length != alg.getKeySize()/8) {
            throw new CoseException("Key Size is incorrect");
        }

        // get and validate iv
        if (iv == null) {
            throw new CoseException("Missing IV during decryption");
        }
        if (iv.getType() != CBORType.ByteString) {
            throw new CoseException("IV is incorrectly formed");
        }
        if (iv.GetByteString().length != AES_GCM_IV_LENGTH/8) {
            throw new CoseException("IV size is incorrect");
        }

        try {
            // create and prepare cipher
            Cipher          cipher;
            cipher = Cipher.getInstance(AES_GCM_SPEC);
            cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(rgbKey, "AES"),
                        new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
            cipher.updateAAD(getAADBytes());

            // setup plaintext output
            rgbContent = new byte[cipher.getOutputSize(rgbEncrypt.length)];

            // decryptit!
            ByteBuffer  input = ByteBuffer.wrap(rgbEncrypt);
            ByteBuffer  output = ByteBuffer.wrap(rgbContent);
            cipher.doFinal(input, output);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Decryption failure", ex);
        }
    }

    private void AES_GCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException, InvalidCipherTextException {
        // validate key
        if (rgbKey.length != alg.getKeySize()/8) {
            throw new CoseException("Key Size is incorrect");
        }
        
        // obtain and validate iv
        CBORObject  iv = findAttribute(HeaderKeys.IV);
        if (iv == null) {
            // generate IV
            byte[] tmp = new byte[AES_GCM_IV_LENGTH/8];
            random.nextBytes(tmp);
            iv = CBORObject.FromObject(tmp);
            addAttribute(HeaderKeys.IV, iv, PROTECTED);
        } else {
            if (iv.getType() != CBORType.ByteString) {
                throw new CoseException("IV is incorrectly formed");
            }
            if (iv.GetByteString().length != AES_GCM_IV_LENGTH/8) {
                throw new CoseException("IV size is incorrect");
            }
        }
        
        try {
            Cipher      cipher = Cipher.getInstance(AES_GCM_SPEC);
            cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(rgbKey, AES_SPEC),
                        new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
            cipher.updateAAD(getAADBytes());

            rgbEncrypt = new byte[cipher.getOutputSize(rgbContent.length)];
            ByteBuffer  input = ByteBuffer.wrap(rgbContent);
            ByteBuffer  output = ByteBuffer.wrap(rgbEncrypt);
            cipher.doFinal(input, output);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Encryption failure", ex);
        }
    }
    
    private byte[] getAADBytes() {
        CBORObject obj = CBORObject.NewArray();
        
        obj.Add(context);
        if (objProtected.size() == 0) obj.Add(CBORObject.FromObject(new byte[0]));
        else obj.Add(objProtected.EncodeToBytes());
        obj.Add(CBORObject.FromObject(externalData));
        return obj.EncodeToBytes();
    }
    
    /**
     * Used to obtain the encrypted content for the cases where detached content
     * is requested.
     * 
     * @return bytes of the encrypted content
     * @throws CoseException if content has not been encrypted
     */
    public byte[] getEncryptedContent() throws CoseException{
        if (rgbEncrypt == null) throw new CoseException("No Encrypted Content Specified");
        
        return rgbEncrypt;
    }
    
    /**
     * Set the encrypted content for detached content cases.
     * 
     * @param rgb encrypted content to be used
     */
    public void setEncryptedContent(byte[] rgb) {
        rgbEncrypt = rgb;
    }
}
