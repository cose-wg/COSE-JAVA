/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package test;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.MAC0Message;
import COSE.MACMessage;
import COSE.Message;
import COSE.Recipient;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.stream.Stream;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author jimsch
 */
public class Test {

    public static int CFails = 0;
        
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
             
        ProcessDirectory("c:\\Projects\\cose\\Examples\\aes-gcm-examples");
        ProcessDirectory("c:\\Projects\\cose\\Examples\\hmac-examples");

        if (CFails == 0) System.out.print("SUCCEEDED");
        else System.out.print("FAILED");
    }
 
    public static void ProcessDirectory(String folder) {
        File directory = new File(folder);
        File[] contents = directory.listFiles();
        for ( File f : contents) {
            ProcessFile(f.getAbsolutePath());
        }       
    }

    public static void ProcessFile(String test) {
        
        try {
            InputStream str = new FileInputStream(test);
            CBORObject foo = CBORObject.ReadJSON(str);

            ProcessJSON(foo);
        }
        catch(Exception e) {
            
        }
    }
    
    public static void ProcessJSON(CBORObject control) {
        CBORObject input = control.get("input");
        
        if (input.ContainsKey("mac0")) {
            VerifyMac0Test(control);
        }
        else if (input.ContainsKey("mac")) {
            VerifyMacTest(control);
        }
        else if (input.ContainsKey("encrypted")) {
            VerifyEncryptTest(control);
        }
    }
    
    public static void VerifyEncryptTest(CBORObject control) {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyEncrypt(control, rgb);
    }
    
    public static void _VerifyEncrypt(CBORObject control, byte[] rgbData) {
 	CBORObject pInput = control.get("input");
	boolean fFail = false;
	boolean fFailBody = false;

        CBORObject pFail = control.get("fail");
        if ((pFail != null) && (pFail.getType() == CBORType.Boolean) &&
              pFail.AsBoolean()) {
            fFailBody = true;
        }

        try {
            Message msg = Message.DecodeFromBytes(rgbData, 0);
            Encrypt0Message enc0 = (Encrypt0Message)msg;

            CBORObject cnEncrypt = pInput.get("encrypted");
            SetReceivingAttributes(msg, cnEncrypt, 2);

            CBORObject cnRecipients = cnEncrypt.get("recipients");
            cnRecipients = cnRecipients.get(0);

            CBORObject cnKey = BuildKey(cnRecipients.get("key"), true);

            CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

            pFail = cnRecipients.get("fail");

            try {
            byte[] rgbContent = enc0.Decrypt(kk.GetByteString());
                if ((pFail != null) && !pFail.AsBoolean()) CFails++;
            }
            catch (Exception e) {
                   if ((pFail != null) && pFail.AsBoolean()) CFails ++;
            }            
        }
        catch (Exception e) {
            CFails++;
        }
    }
    
    public static void VerifyMac0Test(CBORObject control) {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyMac0(control, rgb);
    }
    
    public static void _VerifyMac0(CBORObject control, byte[] rgbData) {
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
            CFails++;
        }
    }

    public static void VerifyMacTest(CBORObject control) {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyMac(control, rgb);
    }
    
    public static void _VerifyMac(CBORObject control, byte[] rgbData) {
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
    
    public static void SetReceivingAttributes(Message msg, CBORObject cnIn, int base) throws Exception
    {
	boolean f = false;

	SetAttributes(msg, cnIn.get("unsent"), /*COSE_DONT_SEND*/ 2, base, true);

        CBORObject cnExternal = cnIn.get("external");
	if (cnExternal != null) {
            msg.SetExternal(hexStringToByteArray(cnExternal.AsString()));
        }
    }
    
    public static void SetAttributes(Message msg, CBORObject cnAttributes, int which, int msgType, boolean fPublicKey) throws Exception {
        if (cnAttributes == null) return;
        
        for (CBORObject attr : cnAttributes.getKeys()) {
            switch (attr.AsString()) {
                default:
                    throw new Exception("Attribute " + attr.AsString() + " is not part of SetAttributes");
            }
        }
    }
    
    public static CBORObject BuildKey(CBORObject keyIn, boolean fPublicKey) {
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
            
            
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }    
}
