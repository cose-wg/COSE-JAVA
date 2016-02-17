/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import org.junit.*;
import COSE.*;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.crypto.InvalidCipherTextException;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.*;

/**
 *
 * @author jimsch
 */
@RunWith(Parameterized.class)
public class RegressionTest {
    @Parameters
    public static Collection<Object> data() {
        return Arrays.asList(new Object[] {
            "Examples/aes-ccm-examples",
            "Examples/aes-gcm-examples",
            "Examples/cbc-mac-examples",
            "Examples/encrypted-tests",
            "Examples/hmac-examples",
            "Examples/mac0-tests"
           });
    }

    @Parameter // first data value (0) is default
    public /* NOT private */ String directoryName;

    public int CFails = 0;
         
    @Test
    public void ProcessDirectory() {
        CFails=0;
        File directory = new File(directoryName);
        if (!directory.isDirectory()) {
            directory = new File("C:\\Projects\\cose\\" + directoryName);
        }
        File[] contents = directory.listFiles();
        for ( File f : contents) {
            ProcessFile(f.getAbsolutePath());
        }    
        assertEquals(0, CFails);
    }

    public void ProcessFile(String test) {
        
        try {
            int fails = CFails;
            System.out.print("Check: " + test);
            InputStream str = new FileInputStream(test);
            CBORObject foo = CBORObject.ReadJSON(str);

            ProcessJSON(foo);
            if (fails == CFails) System.out.print("... PASS\n");
            else System.out.print("... FAIL\n");
        }
        catch(Exception e) {
            System.out.print("... FAIL\nException " + e + "\n");
            CFails++;
        }
    }
    
    public void ProcessJSON(CBORObject control) throws CoseException, IllegalStateException, InvalidCipherTextException, Exception {
        CBORObject input = control.get("input");
        
        if (input.ContainsKey("mac0")) {
            VerifyMac0Test(control);
            BuildMac0Test(control);
        }
        else if (input.ContainsKey("mac")) {
            VerifyMacTest(control);
        }
        else if (input.ContainsKey("encrypted")) {
            VerifyEncryptTest(control);
            BuildEncryptTest(control);
            
        }
    }
    
    public void BuildEncryptTest(CBORObject cnControl) throws CoseException, IllegalStateException, InvalidCipherTextException, Exception {
        CBORObject cnFail = cnControl.get("fail");
        if ((cnFail != null) && cnFail.AsBoolean()) return;
        
        CBORObject cnInput = cnControl.get("input");
        CBORObject cnEncrypt = cnInput.get("encrypted");
        
        Encrypt0Message msg = new Encrypt0Message();
        
        CBORObject cn = cnInput.get("plaintext");
        msg.SetContent(cn.AsString());
        
        SetSendingAttributes(msg, cnEncrypt, true);

        CBORObject cnRecipients = cnEncrypt.get("recipients");
        cnRecipients = cnRecipients.get(0);

        CBORObject cnKey = BuildKey(cnRecipients.get("key"), true);

        CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

        msg.Encrypt(kk.GetByteString());
        
        byte[] rgb = msg.EncodeToBytes();
        
        _VerifyEncrypt(cnControl, rgb);
    }
    
    public void VerifyEncryptTest(CBORObject control) {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyEncrypt(control, rgb);
    }
    
    public void _VerifyEncrypt(CBORObject control, byte[] rgbData) {
 	CBORObject cnInput = control.get("input");
	boolean fFail = false;
	boolean fFailBody = false;

        CBORObject cnFail = control.get("fail");
        if ((cnFail != null) && (cnFail.getType() == CBORType.Boolean) &&
              cnFail.AsBoolean()) {
            fFailBody = true;
        }

        try {
            Message msg = Message.DecodeFromBytes(rgbData, 993);
            Encrypt0Message enc0 = (Encrypt0Message)msg;

            CBORObject cnEncrypt = cnInput.get("encrypted");
            SetReceivingAttributes(msg, cnEncrypt, 2);

            CBORObject cnRecipients = cnEncrypt.get("recipients");
            cnRecipients = cnRecipients.get(0);

            CBORObject cnKey = BuildKey(cnRecipients.get("key"), true);

            CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

            cnFail = cnRecipients.get("fail");

            try {
                byte[] rgbContent = enc0.Decrypt(kk.GetByteString());
                if ((cnFail != null) && !cnFail.AsBoolean()) CFails++;
                byte[] oldContent = cnInput.get("plaintext").AsString().getBytes(StandardCharsets.UTF_8);
                assertArrayEquals(oldContent, rgbContent);
            }
            catch (Exception e) {
                   if (!fFailBody && ((cnFail == null) || !cnFail.AsBoolean())) CFails ++;
            }            
        }
        catch (Exception e) {
            if (!fFailBody) CFails++;
        }
    }
    
    public void BuildMac0Test(CBORObject cnControl) throws CoseException, IllegalStateException, InvalidCipherTextException, Exception {
        CBORObject cnFail = cnControl.get("fail");
        if ((cnFail != null) && cnFail.AsBoolean()) return;
        
        CBORObject cnInput = cnControl.get("input");
        CBORObject cnEncrypt = cnInput.get("mac0");
        
        MAC0Message msg = new MAC0Message();
        
        CBORObject cn = cnInput.get("plaintext");
        msg.SetContent(cn.AsString());
        
        SetSendingAttributes(msg, cnEncrypt, true);

        CBORObject cnRecipients = cnEncrypt.get("recipients");
        cnRecipients = cnRecipients.get(0);

        CBORObject cnKey = BuildKey(cnRecipients.get("key"), true);

        CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

        msg.Create(kk.GetByteString());
        
        byte[] rgb = msg.EncodeToBytes();
        
        _VerifyMac0(cnControl, rgb);
    }

    public void VerifyMac0Test(CBORObject control) {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyMac0(control, rgb);
    }
    
    public void _VerifyMac0(CBORObject control, byte[] rgbData) {
	CBORObject pInput = control.get("input");
	int type;
	boolean fFail = false;
	boolean fFailBody = false;

        try {
            CBORObject pFail = control.get("fail");
            if ((pFail != null) && (pFail.getType() == CBORType.Boolean) &&
                  pFail.AsBoolean()) {
                fFailBody = true;
            }

            Message msg = Message.DecodeFromBytes(rgbData, 996);
            MAC0Message mac0 = (MAC0Message)msg;

            CBORObject cnMac = pInput.get("mac0");
            SetReceivingAttributes(msg, cnMac, 2);

            CBORObject cnRecipients = cnMac.get("recipients");
            cnRecipients = cnRecipients.get(0);

            CBORObject cnKey = BuildKey(cnRecipients.get("key"), true);

            CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

            pFail = cnRecipients.get("fail");

            boolean f = mac0.Validate(kk.GetByteString());

            if (f) {
               if ((pFail != null) && pFail.AsBoolean()) CFails ++;
            }
            else {
                if ((pFail != null) && !pFail.AsBoolean()) CFails++;
            }

        }
        catch (Exception e) {
            if (!fFailBody) CFails++;
        }
    }

    public void VerifyMacTest(CBORObject control) {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyMac(control, rgb);
    }
    
    public void _VerifyMac(CBORObject control, byte[] rgbData) {
	CBORObject pInput = control.get("input");
	int type;
	boolean fFail = false;
	boolean fFailBody = false;

        try {
            CBORObject pFail = control.get("fail");
            if ((pFail != null) && (pFail.getType() == CBORType.Boolean) &&
                  pFail.AsBoolean()) {
                fFailBody = true;
            }

            Message msg = Message.DecodeFromBytes(rgbData, 0);
            MACMessage mac = (MACMessage)msg;

            CBORObject cnMac = pInput.get("mac");
            SetReceivingAttributes(msg, cnMac, 2);

            CBORObject cnRecipients = cnMac.get("recipients");
            cnRecipients = cnRecipients.get(0);

            CBORObject cnKey = BuildKey(cnRecipients.get("key"), true);
            Recipient recipient = mac.GetRecipient(0);
            recipient.SetKey(cnKey);

            pFail = cnRecipients.get("fail");

            boolean f = mac.Validate(recipient);

            if (f) {
               if ((pFail != null) && pFail.AsBoolean()) CFails ++;
            }
            else {
                if ((pFail != null) && !pFail.AsBoolean()) CFails++;
            }

        }
        catch (Exception e) {
            CFails++;
        }
    }
    
    public void SetReceivingAttributes(Message msg, CBORObject cnIn, int base) throws Exception
    {
	boolean f = false;

	SetAttributes(msg, cnIn.get("unsent"), Attribute.DontSendAttributes, true);

        CBORObject cnExternal = cnIn.get("external");
	if (cnExternal != null) {
            msg.SetExternal(hexStringToByteArray(cnExternal.AsString()));
        }
    }
    
    void SetSendingAttributes(Message msg, CBORObject cnIn, boolean fPublicKey) throws Exception
    {
        SetAttributes(msg, cnIn.get("protected"), Attribute.ProtectedAttributes, fPublicKey);
        SetAttributes(msg, cnIn.get("unprotected"), Attribute.UnprotectedAttributes, fPublicKey);
        SetAttributes(msg, cnIn.get("unsent"), Attribute.DontSendAttributes, fPublicKey);

        CBORObject cnExternal = cnIn.get("external");
        if (cnExternal != null) {
            msg.SetExternal(hexStringToByteArray(cnExternal.AsString()));
        }
    }

    
    public void SetAttributes(Message msg, CBORObject cnAttributes, int which, boolean fPublicKey) throws Exception {
        if (cnAttributes == null) return;
        
        CBORObject cnKey;
        CBORObject cnValue;
        
        for (CBORObject attr : cnAttributes.getKeys()) {
            switch (attr.AsString()) {
                case "alg":
                    cnKey = HeaderKeys.Algorithm.AsCBOR();
                    cnValue = AlgorithmMap(cnAttributes.get(attr));
                    break;
                    
                case "kid":
                    cnKey= HeaderKeys.KID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                default:
                    throw new Exception("Attribute " + attr.AsString() + " is not part of SetAttributes");
            }
            
            msg.addAttribute(cnKey, cnValue, which);
        }
    }
    
    public CBORObject BuildKey(CBORObject keyIn, boolean fPublicKey) {
        CBORObject cnKeyOut = CBORObject.NewMap();
 
        for (CBORObject key : keyIn.getKeys()) {
            CBORObject cnValue = keyIn.get(key);
            
            switch (key.AsString()) {
                case "kty":
                    switch (cnValue.AsString()) {
                        case "EC":
                            cnKeyOut.set(CBORObject.FromObject(1), CBORObject.FromObject(2));
                            break;
                            
                        case "oct":
                            cnKeyOut.set(CBORObject.FromObject(1), CBORObject.FromObject(4));
                            break;
                    }
                    break;
                    
                case "crv":
                    switch (cnValue.AsString()) {
                        case "P-256":
                            cnValue = CBORObject.FromObject(1);
                            break;
                            
                        case "P-384":
                            cnValue = CBORObject.FromObject(2);
                            break;
                            
                        case "P-521":
                            cnValue = CBORObject.FromObject(3);
                            break;
                    }
                    
                            
                    cnKeyOut.set(CBORObject.FromObject(-1), cnValue);
                    break;
                    
                case "k":
                    cnKeyOut.set(CBORObject.FromObject(-1), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;
            }
        }
        
        return cnKeyOut;
    }
            
            
    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }  
    
    static CBORObject AlgorithmMap(CBORObject old)
     {
         if (old.getType() == CBORType.Number) {
             return old;
         }

         switch (old.AsString()) {
         case "A128GCM": return AlgorithmID.AES_GCM_128.AsCBOR();
         case "A192GCM": return AlgorithmID.AES_GCM_192.AsCBOR();
         case "A256GCM": return AlgorithmID.AES_GCM_256.AsCBOR();
         // case "A128KW": return AlgorithmID.AES_KW_128.AsCBOR();
         // case "A192KW": return AlgorithmID.AES_KW_192.AsCBOR();
         // case "A256KW": return AlgorithmID.AES_KW_256.AsCBOR();
         // case "RSA-OAEP": return AlgorithmID.RSA_OAEP.AsCBOR();
         // case "RSA-OAEP-256": return AlgorithmID.RSA_OAEP_256.AsCBOR();
         case "HS256": return AlgorithmID.HMAC_SHA_256.AsCBOR();
         case "HS256/64": return AlgorithmID.HMAC_SHA_256_64.AsCBOR();
         case "HS384": return AlgorithmID.HMAC_SHA_384.AsCBOR();
         case "HS512": return AlgorithmID.HMAC_SHA_512.AsCBOR();
         // case "ES256": return AlgorithmID.ECDSA_256.AsCBOR();
         // case "ES384": return AlgorithmID.ECDSA_384.AsCBOR();
         // case "ES512": return AlgorithmID.ECDSA_512.AsCBOR();
         // case "PS256": return AlgorithmID.RSA_PSS_256.AsCBOR();
         // case "PS512": return AlgorithmID.RSA_PSS_512.AsCBOR();
         // case "direct": return AlgorithmID.Direct.AsCBOR();
         // case "AES-CMAC-128/64": return AlgorithmID.AES_CMAC_128_64.AsCBOR();
         // case "AES-CMAC-256/64": return AlgorithmID.AES_CMAC_256_64.AsCBOR();
         case "AES-MAC-128/64": return AlgorithmID.AES_CBC_MAC_128_64.AsCBOR();
         case "AES-MAC-256/64": return AlgorithmID.AES_CBC_MAC_256_64.AsCBOR();
         case "AES-MAC-128/128": return AlgorithmID.AES_CBC_MAC_128_128.AsCBOR();
         case "AES-MAC-256/128": return AlgorithmID.AES_CBC_MAC_256_128.AsCBOR();
         case "AES-CCM-16-128/64": return AlgorithmID.AES_CCM_16_64_128.AsCBOR();
         case "AES-CCM-16-128/128": return AlgorithmID.AES_CCM_16_128_128.AsCBOR();
         case "AES-CCM-16-256/64": return AlgorithmID.AES_CCM_16_64_256.AsCBOR();
         case "AES-CCM-16-256/128": return AlgorithmID.AES_CCM_16_128_256.AsCBOR();
         case "AES-CCM-64-128/64": return AlgorithmID.AES_CCM_64_64_128.AsCBOR();
         case "AES-CCM-64-128/128": return AlgorithmID.AES_CCM_64_128_128.AsCBOR();
         case "AES-CCM-64-256/64": return AlgorithmID.AES_CCM_64_64_256.AsCBOR();
         case "AES-CCM-64-256/128": return AlgorithmID.AES_CCM_64_128_256.AsCBOR();
         // case "HKDF-HMAC-SHA-256": return AlgorithmID.HKDF_HMAC_SHA_256.AsCBOR();
         // case "HKDF-HMAC-SHA-512": return AlgorithmID.HKDF_HMAC_SHA_512.AsCBOR();
         // case "HKDF-AES-128": return AlgorithmID.HKDF_AES_128.AsCBOR();
         // case "HKDF-AES-256": return AlgorithmID.HKDF_AES_256.AsCBOR();
         // case "ECDH-ES": return AlgorithmID.ECDH_ES_HKDF_256.AsCBOR();
         // case "ECDH-ES-512": return AlgorithmID.ECDH_ES_HKDF_512.AsCBOR();
         // case "ECDH-SS": return AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
         // case "ECDH-SS-256": return AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
         // case "ECDH-SS-512": return AlgorithmID.ECDH_SS_HKDF_512.AsCBOR();
         // case "ECDH-ES+A128KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_128.AsCBOR();
         // case "ECDH-SS+A128KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_128.AsCBOR();
         // case "ECDH-ES-A128KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_128.AsCBOR();
         // case "ECDH-SS-A128KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_128.AsCBOR();
         // case "ECDH-ES-A192KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_192.AsCBOR();
         // case "ECDH-SS-A192KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_192.AsCBOR();
         // case "ECDH-ES-A256KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_256.AsCBOR();
         // case "ECDH-SS-A256KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_256.AsCBOR();

         default: return old;
         }
     }
}
