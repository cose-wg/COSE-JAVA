/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

/**
 *
 * @author jimsch
 */

public abstract class SignCommon extends Message {
    protected String contextString;

    byte[] computeSignature(byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return computeSignature(alg, rgbToBeSigned, cnKey);
    }

    static byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        String      algName = null;
        int         sigLen = 0;
        
        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                sigLen = 32;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                sigLen = 48;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                sigLen = 66;
                break;
            case EDDSA:
                algName = "NonewithEdDSA";
                break;
                
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        if (cnKey == null) {
            throw new NullPointerException();
        }
        
        PrivateKey  privKey = cnKey.AsPrivateKey();
        if (privKey == null) {
            throw new CoseException("Private key required to sign");
        }
        
        byte[]      result = null;
        try {
            Signature sig = Signature.getInstance(algName);
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            result = sig.sign();
            if (sigLen > 0) {
                result = convertDerToConcat(result, sigLen);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }
        
        return result;
    }
    
    private static byte[] convertDerToConcat(byte[] der, int len) throws CoseException {
        // this is far too naive
        byte[] concat = new byte[len * 2];

        // assumes SEQUENCE is organized as "R + S"
        int kLen = 4;
        if (der[0] != 0x30) {
            throw new CoseException("Unexpected signature input");
        }
        if ((der[1] & 0x80) != 0) {
            // offset actually 4 + (7-bits of byte 1)
            kLen = 4 + (der[1] & 0x7f);
        }
        
        // calculate start/end of R
        int rOff = kLen;
        int rLen = der[rOff - 1];
        int rPad = 0;
        if (rLen > len) {
            rOff += (rLen - len);
            rLen = len;
        } else {
            rPad = (len - rLen);
        }
        // copy R
        System.arraycopy(der, rOff, concat, rPad, rLen);
        
        // calculate start/end of S
        int sOff = rOff + rLen + 2;
        int sLen = der[sOff - 1];
        int sPad = 0;
        if (sLen > len) {
            sOff += (sLen - len);
            sLen = len;
        } else {
            sPad = (len - sLen);
        }
        // copy S
        System.arraycopy(der, sOff, concat, len + sPad, sLen);
        
        return concat;
    }
    
    boolean validateSignature(byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return validateSignature(alg, rgbToBeSigned, rgbSignature, cnKey);
    }

    static boolean validateSignature(AlgorithmID alg, byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey) throws CoseException {
        String algName = null;
        boolean convert = false;

        switch (alg) {
        case ECDSA_256:
            algName = "SHA256withECDSA";
            convert = true;
            break;
        case ECDSA_384:
            algName = "SHA384withECDSA";
            convert = true;
            break;
        case ECDSA_512:
            algName = "SHA512withECDSA";
            convert = true;
            break;
            
        case EDDSA:
            algName = "NonewithEdDSA";
            break;

        default:
            throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PublicKey pubKey = cnKey.AsPublicKey();
        if (pubKey == null) {
            throw new CoseException("Public key required to verify");
        }

        boolean result = false;
        try {
            Signature sig = Signature.getInstance(algName);
            sig.initVerify(pubKey);
            sig.update(rgbToBeSigned);

            if (convert) {
                rgbSignature = convertConcatToDer(rgbSignature);
            }
            result = sig.verify(rgbSignature);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature verification failure", ex);
        }

        return result;
    }

    private static byte[] convertConcatToDer(byte[] concat) throws CoseException {
        int len = concat.length / 2;
        byte[] r = Arrays.copyOfRange(concat, 0, len);
        byte[] s = Arrays.copyOfRange(concat, len, concat.length);

        return ASN1.EncodeSignature(r, s);
    }
}
