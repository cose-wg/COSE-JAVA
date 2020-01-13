/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import org.junit.*;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
public class RegressionTest extends TestBase {
    @Parameters(name = "{index}: {0})")
    public static Collection<Object> data() {
        return Arrays.asList(new Object[] {
            // "Examples/X509",
            // "Examples/anima",
            "Examples/countersign",
            "Examples/countersign0",
            "Examples/eddsa-examples",
            "Examples/aes-ccm-examples",
            "Examples/aes-gcm-examples",
            "Examples/aes-wrap-examples",
            "Examples/cbc-mac-examples",
            "Examples/ecdh-direct-examples",
            "Examples/ecdh-wrap-examples",
            "Examples/ecdsa-examples",
            "Examples/encrypted-tests",
            "Examples/enveloped-tests",
            "Examples/hkdf-hmac-sha-examples",
            "Examples/hmac-examples",
            "Examples/mac-tests",
            "Examples/mac0-tests",
            "Examples/sign-tests",
            "Examples/sign1-tests",
            "Examples/RFC8152",
            "Examples/rsa-pss-examples",
            // "Examples/X509",
            "Examples/CWT"
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
            directory = new File("D:\\Projects\\cose\\" + directoryName);
        }
        File[] contents = directory.listFiles();
        org.junit.Assert.assertNotNull(directoryName, contents);
        for ( File f : contents) {
            ProcessFile(f.getAbsolutePath());
        }    
        assertEquals(0, CFails);
    }

    public void ProcessFile(String test) {
        
        if (!test.endsWith(".json")) return;
        try {
            int fails = CFails;
            System.out.print("Check: " + test);
            InputStream str = new FileInputStream(test);
            CBORObject foo = CBORObject.ReadJSON(str);
            

            ProcessJSON(foo);
            if (fails == CFails) System.out.print("... PASS\n");
            else System.out.print("... FAIL\n");
        }
        catch (CoseException e) {
            if (e.getMessage().equals("Unsupported key size") || 
                e.getMessage().equals("Unsupported Algorithm")) {
                System.out.print("... SKIP\nException " + e + "\n");                
            }
            else {
                System.out.print("... FAIL\nException " + e + "\n");                
                CFails++;            
            }
        }
        catch(Exception e) {
            System.out.print("... FAIL\nException " + e + "\n");
            CFails++;
        }
    }
    
    public void ProcessJSON(CBORObject control) throws CoseException, IllegalStateException, Exception {
        CBORObject input = control.get("input");
        
        if (input.ContainsKey("mac0")) {
            VerifyMac0Test(control);
            BuildMac0Test(control);
        }
        else if (input.ContainsKey("mac")) {
            VerifyMacTest(control);
            BuildMacTest(control);
        }
        else if (input.ContainsKey("encrypted")) {
            VerifyEncryptTest(control);
            BuildEncryptTest(control);
        }
        else if (input.ContainsKey("enveloped")) {
            VerifyEnvelopedTest(control);
            BuildEnvelopedTest(control);
        }
        else if (input.ContainsKey("sign")) {
            ValidateSigned(control);
            BuildSignedMessage(control);
        }
        else if (input.ContainsKey("sign0")) {
            ValidateSign0(control);
            BuildSign0Message(control);
        }
    }
    
    public void BuildEncryptTest(CBORObject cnControl) throws CoseException, IllegalStateException, Exception {
        CBORObject cnFail = cnControl.get("fail");
        if ((cnFail != null) && cnFail.AsBoolean()) return;
        
        CBORObject cnInput = cnControl.get("input");
        CBORObject cnEncrypt = cnInput.get("encrypted");
        
        Encrypt0Message msg = new Encrypt0Message();
        
        CBORObject cn = cnInput.get("plaintext");
        if (cn == null) {
            cn = cnInput.get("plaintext_hex");
            msg.SetContent(hexStringToByteArray(cn.AsString()));
        }
        else {
            msg.SetContent(cn.AsString());
        }
        SetSendingAttributes(msg, cnEncrypt, true);

        if (cnEncrypt.ContainsKey("countersign0")) {
            AddCounterSignature0(msg, cnEncrypt.get("countersign0"));
        }
        
        if (cnEncrypt.ContainsKey("countersign")) {
            AddCounterSignature(msg, cnEncrypt.get("countersign"));
        }
        
        CBORObject cnRecipients = cnEncrypt.get("recipients");
        cnRecipients = cnRecipients.get(0);

        OneKey cnKey = BuildKey(cnRecipients.get("key"), true);

        CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

        msg.encrypt(kk.GetByteString());
        
        byte[] rgb = msg.EncodeToBytes();
        
        _VerifyEncrypt(cnControl, rgb);
    }
    
    public void VerifyEncryptTest(CBORObject control) throws CoseException {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyEncrypt(control, rgb);
    }
    
    public void _VerifyEncrypt(CBORObject control, byte[] rgbData) throws CoseException {
 	CBORObject cnInput = control.get("input");
	boolean fFail = false;
	boolean fFailBody = false;

        CBORObject cnFail = control.get("fail");
        if ((cnFail != null) && (cnFail.getType() == CBORType.Boolean) &&
              cnFail.AsBoolean()) {
            fFailBody = true;
        }

        try {
            Message msg;
            try {
                msg = Message.DecodeFromBytes(rgbData, MessageTag.Encrypt0);
            }
            catch (Exception e) {
               if (!fFailBody && ((cnFail == null) || !cnFail.AsBoolean())) CFails ++;
               throw new Exception();
            }
            Encrypt0Message enc0 = (Encrypt0Message)msg;

            CBORObject cnEncrypt = cnInput.get("encrypted");
            SetReceivingAttributes(msg, cnEncrypt);

            CBORObject cnRecipients = cnEncrypt.get("recipients");
            cnRecipients = cnRecipients.get(0);

            OneKey cnKey = BuildKey(cnRecipients.get("key"), true);

            CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

            cnFail = cnRecipients.get("fail");

            try {
                byte[] rgbContent = enc0.decrypt(kk.GetByteString());
                if ((cnFail != null) && !cnFail.AsBoolean()) CFails++;
                
                byte[] oldContent;
                CBORObject cnOldContent = cnInput.get("plaintext");
                if (cnOldContent == null) {
                    cnOldContent = cnInput.get("plaintext_hex");
                    oldContent = hexStringToByteArray(cnOldContent.AsString());
                }
                else {
                    oldContent = cnInput.get("plaintext").AsString().getBytes(StandardCharsets.UTF_8);
                }
                                
                assertArrayEquals(oldContent, rgbContent);
            }
            catch(CoseException e) {
                if (e.getMessage() == "Unsupported key size") {
                    throw e;
                }
               if (!fFailBody && ((cnFail == null) || !cnFail.AsBoolean())) CFails ++;
            }
            catch (Exception e) {
               if (!fFailBody && ((cnFail == null) || !cnFail.AsBoolean())) CFails ++;
            }

            CBORObject cnCounter = cnEncrypt.get("countersign0");
            if (cnCounter != null) {
                CheckCounterSignature0(msg, cnCounter);
            }

            cnCounter = cnEncrypt.get("countersign");
            if (cnCounter != null) {
                CheckCounterSignatures(msg, cnCounter);
            }
        }
        catch (CoseException e) {
            throw e;
        }
        catch (Exception e) {
            if (!fFailBody) CFails++;
        }
    }

    void BuildMacTest(CBORObject cnControl) throws Exception
    {
	int iRecipient;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

        if (HasFailMarker(cnControl)) return;

	MACMessage hEncObj = new MACMessage();

	CBORObject cnInputs = cnControl.get("input");
	CBORObject cnEnveloped = cnInputs.get("mac");

	CBORObject cnContent = cnInputs.get("plaintext");
        if (cnContent == null) {
            cnContent = cnInputs.get("plaintext_hex");
            hEncObj.SetContent(hexStringToByteArray(cnContent.AsString()));
        }
        else {
            hEncObj.SetContent(cnContent.AsString());
        }

	SetSendingAttributes(hEncObj, cnEnveloped, true);
        
        if (cnEnveloped.ContainsKey("countersign0")) {
            AddCounterSignature0(hEncObj, cnEnveloped.get("countersign0"));
        }
        
        if (cnEnveloped.ContainsKey("countersign")) {
            AddCounterSignature(hEncObj, cnEnveloped.get("countersign"));
        }

	CBORObject cnRecipients = cnEnveloped.get("recipients");

	for (iRecipient = 0; iRecipient<cnRecipients.size(); iRecipient++) {
            Recipient hRecip = BuildRecipient(cnRecipients.get(iRecipient));

            hEncObj.addRecipient(hRecip);
	}

	hEncObj.Create();

        byte[] rgb = hEncObj.EncodeToBytes();

	_VerifyMac(cnControl, rgb);

        return;
    }
    
    public void BuildMac0Test(CBORObject cnControl) throws CoseException, IllegalStateException, Exception {
        CBORObject cnFail = cnControl.get("fail");
        if ((cnFail != null) && cnFail.AsBoolean()) return;
        
        CBORObject cnInput = cnControl.get("input");
        CBORObject cnEncrypt = cnInput.get("mac0");
        
        MAC0Message msg = new MAC0Message();
        
        CBORObject cn = cnInput.get("plaintext");
        if (cn == null) {
            cn = cnInput.get("plaintext_hex");
            msg.SetContent(hexStringToByteArray(cn.AsString()));
        }
        else {
            msg.SetContent(cn.AsString());
        }
        
        SetSendingAttributes(msg, cnEncrypt, true);
        
        if (cnEncrypt.ContainsKey("countersign0")) {
            AddCounterSignature0(msg, cnEncrypt.get("countersign0"));
        }
        
        if (cnEncrypt.ContainsKey("countersign")) {
            AddCounterSignature(msg, cnEncrypt.get("countersign"));
        }

        CBORObject cnRecipients = cnEncrypt.get("recipients");
        cnRecipients = cnRecipients.get(0);

        OneKey cnKey = BuildKey(cnRecipients.get("key"), true);

        CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

        msg.Create(kk.GetByteString());
        
        byte[] rgb = msg.EncodeToBytes();
        
        _VerifyMac0(cnControl, rgb);
    }

    public void VerifyMac0Test(CBORObject control) throws CoseException {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyMac0(control, rgb);
    }
    
    public void _VerifyMac0(CBORObject control, byte[] rgbData) throws CoseException {
	CBORObject cnInput = control.get("input");
	int type;
	boolean fFail = false;
	boolean fFailBody = false;

        try {
            CBORObject pFail = control.get("fail");
            if ((pFail != null) && (pFail.getType() == CBORType.Boolean) &&
                  pFail.AsBoolean()) {
                fFailBody = true;
            }

            Message msg = Message.DecodeFromBytes(rgbData, MessageTag.MAC0);
            MAC0Message mac0 = (MAC0Message)msg;

            CBORObject cnMac = cnInput.get("mac0");
            SetReceivingAttributes(msg, cnMac);

            CBORObject cnRecipients = cnMac.get("recipients");
            cnRecipients = cnRecipients.get(0);

            OneKey cnKey = BuildKey(cnRecipients.get("key"), true);

            CBORObject kk = cnKey.get(CBORObject.FromObject(-1));

            pFail = cnRecipients.get("fail");

            boolean f = mac0.Validate(kk.GetByteString());

            if (f) {
               if ((pFail != null) && pFail.AsBoolean()) CFails ++;
            }
            else {
                if ((pFail != null) && !pFail.AsBoolean()) CFails++;
            }

            CBORObject cnCounter = cnMac.get("countersign0");
            if (cnCounter != null) {
                CheckCounterSignature0(msg, cnCounter);
            }

            cnCounter = cnMac.get("countersign");
            if (cnCounter != null) {
                CheckCounterSignatures(msg, cnCounter);
            }            
        }
        catch(CoseException e) {
            if (e.getMessage() == "Unsupported key size") {
                throw e;
            }
            if (!fFailBody) CFails++;
        }
        catch (Exception e) {
            if (!fFailBody) CFails++;
        }
    }

    public void VerifyMacTest(CBORObject control) throws CoseException {
        String strExample = control.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);
        _VerifyMac(control, rgb);
    }
    
    public void _VerifyMac(CBORObject control, byte[] rgbData) throws CoseException {
	CBORObject cnInput = control.get("input");
	boolean fFail = false;
	boolean fFailBody = false;

        try {
            Message msg = null;
            MACMessage mac = null;
            fFailBody = HasFailMarker(control);

            try {
                msg = Message.DecodeFromBytes(rgbData, MessageTag.MAC);
                mac = (MACMessage)msg;
            }
            catch (CoseException e) {
                if (e.getMessage().startsWith("Passed in tag does not match actual tag") && fFailBody) return;
                CFails++;
                return;
            }

            CBORObject cnMac = cnInput.get("mac");
            SetReceivingAttributes(msg, cnMac);

            CBORObject cnRecipients = cnMac.get("recipients");
            cnRecipients = cnRecipients.get(0);

            OneKey cnKey = BuildKey(cnRecipients.get("key"), false);
            Recipient recipient = mac.getRecipient(0);
            recipient.SetKey(cnKey);
            
            CBORObject cnStatic = cnRecipients.get("sender_key");
            if (cnStatic != null) {
                if (recipient.findAttribute(HeaderKeys.ECDH_SPK) == null) {
                    recipient.addAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnStatic, true).AsCBOR(), Attribute.DO_NOT_SEND);
                }
            }

            fFail = HasFailMarker(cnRecipients);
            try {
                boolean f = mac.Validate(recipient);
                if (f && (fFail || fFailBody)) CFails++;
                else if (!f && !(fFail || fFailBody)) CFails++;
            }
            catch(CoseException e) {
                if (e.getMessage() == "Unsupported key size") {
                    throw e;
                }
                if (fFail || fFailBody) return;
                CFails++;
                return;
            }
            catch (Exception e) {
                if (fFail || fFailBody) return;
                CFails++;
                return;
            }
            
            CBORObject cnCounter = cnMac.get("countersign0");
            if (cnCounter != null) {
                CheckCounterSignature0(msg, cnCounter);
            }

            cnCounter = cnMac.get("countersign");
            if (cnCounter != null) {
                CheckCounterSignatures(msg, cnCounter);
            }
        }
        catch (CoseException e) {
            throw e;
        }
        catch (Exception e) {
            CFails++;
        }
    }

    boolean DecryptMessage(byte[] rgbEncoded, boolean fFailBody, CBORObject cnEnveloped, CBORObject cnRecipient1, int iRecipient1, CBORObject cnRecipient2, int iRecipient2) throws CoseException
    {
	EncryptMessage hEnc;
	Recipient hRecip;
	Recipient hRecip1;
	Recipient hRecip2;
	boolean fRet = false;
	int type;
	OneKey cnkey;
        Message msg;

        try {
            try {
                msg = Message.DecodeFromBytes(rgbEncoded, MessageTag.Encrypt);
            }
            catch (CoseException e) {
                if (fFailBody) return true;
                throw e;
            }

            hEnc = (EncryptMessage) msg;

            //  Set enveloped attributes
            SetReceivingAttributes(hEnc, cnEnveloped);

            //  Set attibutes on base recipient
            hRecip1 = hEnc.getRecipient(iRecipient1);
            SetReceivingAttributes(hRecip1, cnRecipient1);

            if (cnRecipient2 != null) {
                cnkey = BuildKey(cnRecipient2.get("key"), false);

                hRecip2 = hRecip1.getRecipient(iRecipient2);

                //  Set attributes on the recipients we are using.
                SetReceivingAttributes(hRecip2, cnRecipient2);
                hRecip2.SetKey(cnkey);

                CBORObject cnStatic = cnRecipient2.get("sender_key");
                if (cnStatic != null) {
                    if (hRecip2.findAttribute(HeaderKeys.ECDH_SPK) == null) {
                        hRecip2.addAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnStatic, true).AsCBOR(), Attribute.DO_NOT_SEND);
                    }
                }

                hRecip = hRecip2;
            }
            else {
                cnkey = BuildKey(cnRecipient1.get("key"), false);
                hRecip1.SetKey(cnkey);

                CBORObject cnStatic = cnRecipient1.get("sender_key");
                if (cnStatic != null) {
                    if (hRecip1.findAttribute(HeaderKeys.ECDH_SPK) == null) {
                        hRecip1.addAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnStatic, true).AsCBOR(), Attribute.DO_NOT_SEND);
                    }
                }

                hRecip = hRecip1;
            }


            if (!fFailBody) {
                fFailBody |= HasFailMarker(cnRecipient1);
                if (cnRecipient2 != null) fFailBody |= HasFailMarker(cnRecipient2);
            }

            try {
                byte[] rgbOut = hEnc.decrypt(hRecip);
                if (fFailBody) fRet = false;
                else fRet = true;            
            }
            catch(CoseException e) {
                if (e.getMessage() == "Unsupported key size") {
                    throw e;
                }
                if(!fFailBody) fRet = false;
                else fRet = true;
            }
            catch(Exception e) {
                if(!fFailBody) fRet = false;
                else fRet = true;
            }

            CBORObject cnCounter = cnEnveloped.get("countersign0");
            if (cnCounter != null) {
                CheckCounterSignature0(msg, cnCounter);
            }

            cnCounter = cnEnveloped.get("countersign");
            if (cnCounter != null) {
                CheckCounterSignatures(msg, cnCounter);
            }
            
        }
        catch(CoseException e) {
            throw e;
        }
        catch(Exception e) {
            fRet = false;
        }

	return fRet;
}

    int _ValidateEnveloped(CBORObject cnControl, byte[] rgbEncoded) throws CoseException
    {
	CBORObject cnInput = cnControl.get("input");
	CBORObject cnFail;
	CBORObject cnEnveloped;
	CBORObject cnRecipients;
	int iRecipient;
	boolean fFailBody = false;

        fFailBody = HasFailMarker(cnControl);

	cnEnveloped = cnInput.get("enveloped");
	cnRecipients = cnEnveloped.get("recipients");
        
	for (iRecipient=0; iRecipient<cnRecipients.size(); iRecipient++) {
            CBORObject cnRecipient = cnRecipients.get(iRecipient);
            if (!cnRecipient.ContainsKey("recipients")) {
                if (!DecryptMessage(rgbEncoded, fFailBody, cnEnveloped, cnRecipient, iRecipient, null, 0)) CFails++;
            }
            else {
                int iRecipient2;
                CBORObject cnRecipient2 = cnRecipient.get("recipients");
                for (iRecipient2=0; iRecipient2 < cnRecipient2.size(); iRecipient2++) {
                    if (!DecryptMessage(rgbEncoded, fFailBody, cnEnveloped, cnRecipient, iRecipient, cnRecipient2.get(iRecipient2), iRecipient2)) CFails++;
                }
            }
	}
	return 0;
    }

    int VerifyEnvelopedTest(CBORObject cnControl) throws CoseException
    {
        String strExample = cnControl.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);

	return _ValidateEnveloped(cnControl, rgb);
    }

    Recipient BuildRecipient(CBORObject cnRecipient) throws Exception
    {
	Recipient hRecip = new Recipient();

	SetSendingAttributes(hRecip, cnRecipient, true);

	CBORObject cnKey = cnRecipient.get("key");
	if (cnKey != null) {
            OneKey pkey = BuildKey(cnKey, true);

            hRecip.SetKey(pkey);
        }

	cnKey = cnRecipient.get("recipients");
	if (cnKey != null) {
            for (int i=0; i<cnKey.size(); i++) {
		Recipient hRecip2 = BuildRecipient(cnKey.get(i));
		hRecip.addRecipient(hRecip2);
            }
	}

	CBORObject cnSenderKey = cnRecipient.get("sender_key");
	if (cnSenderKey != null) {
            OneKey cnSendKey = BuildKey(cnSenderKey, false);
            CBORObject cnKid = cnSenderKey.get("kid");
            hRecip.SetSenderKey(cnSendKey);
            if (cnKid == null) {
                hRecip.addAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnSenderKey, true).AsCBOR(), Attribute.UNPROTECTED);
            }
            else {
                hRecip.addAttribute(HeaderKeys.ECDH_SKID, cnKid, Attribute.UNPROTECTED);
            }
	}

	return hRecip;
    }

    void BuildEnvelopedTest(CBORObject cnControl) throws Exception
    {
	int iRecipient;

	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

        if (HasFailMarker(cnControl)) return;

	EncryptMessage hEncObj = new EncryptMessage();

	CBORObject cnInputs = cnControl.get("input");
	CBORObject cnEnveloped = cnInputs.get("enveloped");

	CBORObject cnContent = cnInputs.get("plaintext");
        if (cnContent == null) {
            cnContent = cnInputs.get("plaintext_hex");
            hEncObj.SetContent(hexStringToByteArray(cnContent.AsString()));
        }
        else {
            hEncObj.SetContent(cnContent.AsString());
        }

	SetSendingAttributes(hEncObj, cnEnveloped, true);

        if (cnEnveloped.ContainsKey("countersign0")) {
             AddCounterSignature0(hEncObj, cnEnveloped.get("countersign0"));
         }

         if (cnEnveloped.ContainsKey("countersign")) {
             AddCounterSignature(hEncObj, cnEnveloped.get("countersign"));
         }
            
	CBORObject cnRecipients = cnEnveloped.get("recipients");

	for (iRecipient = 0; iRecipient<cnRecipients.size(); iRecipient++) {
            Recipient hRecip = BuildRecipient(cnRecipients.get(iRecipient));

            hEncObj.addRecipient(hRecip);
	}

	hEncObj.encrypt();

        byte[] rgb = hEncObj.EncodeToBytes();

	int f = _ValidateEnveloped(cnControl, rgb);

        return;
    }
    
    public void SetReceivingAttributes(Attribute msg, CBORObject cnIn) throws Exception
    {
	boolean f = false;

	SetAttributes(msg, cnIn.get("unsent"), Attribute.DO_NOT_SEND, true);

        CBORObject cnExternal = cnIn.get("external");
	if (cnExternal != null) {
            msg.setExternal(hexStringToByteArray(cnExternal.AsString()));
        }
    }
    
    void SetSendingAttributes(Attribute msg, CBORObject cnIn, boolean fPublicKey) throws Exception
    {
        SetAttributes(msg, cnIn.get("protected"), Attribute.PROTECTED, fPublicKey);
        SetAttributes(msg, cnIn.get("unprotected"), Attribute.UNPROTECTED, fPublicKey);
        SetAttributes(msg, cnIn.get("unsent"), Attribute.DO_NOT_SEND, fPublicKey);

        CBORObject cnExternal = cnIn.get("external");
        if (cnExternal != null) {
            msg.setExternal(hexStringToByteArray(cnExternal.AsString()));
        }
    }

    
    public void SetAttributes(Attribute msg, CBORObject cnAttributes, int which, boolean fPublicKey) throws Exception {
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
                    
                case "spk_kid":
                    cnKey = HeaderKeys.ECDH_SKID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                case "IV_hex":
                    cnKey = HeaderKeys.IV.AsCBOR();
                    cnValue = CBORObject.FromObject(hexStringToByteArray(cnAttributes.get(attr).AsString()));
                    break;
                    
                case "partialIV_hex":
                    cnKey = HeaderKeys.PARTIAL_IV.AsCBOR();
                    cnValue = CBORObject.FromObject(hexStringToByteArray(cnAttributes.get(attr).AsString()));
                    break;
                    
                case "salt":
                    cnKey = HeaderKeys.HKDF_Salt.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                case "apu_id":
                    cnKey = HeaderKeys.HKDF_Context_PartyU_ID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                case "apv_id":
                    cnKey = HeaderKeys.HKDF_Context_PartyV_ID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                case "apu_nonce":
                case "apu_nonce_hex":
                    cnKey = HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                case "apv_nonce":
                    cnKey = HeaderKeys.HKDF_Context_PartyV_nonce.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apu_other":
                    cnKey = HeaderKeys.HKDF_Context_PartyU_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apv_other":
                    cnKey = HeaderKeys.HKDF_Context_PartyV_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "pub_other":
                    cnKey = HeaderKeys.HKDF_SuppPub_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;
                    
                case "priv_other":
                    cnKey = HeaderKeys.HKDF_SuppPriv_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "ctyp":
                    cnKey = HeaderKeys.CONTENT_TYPE.AsCBOR();
                    cnValue = cnAttributes.get(attr);
                    break;
                    
                case "crit":
                    cnKey = HeaderKeys.CriticalHeaders.AsCBOR();
                    cnValue = CBORObject.NewArray();
                    for (CBORObject x : cnAttributes.get(attr).getValues()) {
                        cnValue.Add(HeaderMap(x));
                    }
                    break;
                    
                case "reserved":
                    cnKey = attr;
                    cnValue = cnAttributes.get(attr);
                    break;
                    
                case "epk":
                    cnKey = null;
                    cnValue = null;
                    break;
                    
                default:
                    throw new Exception("Attribute " + attr.AsString() + " is not part of SetAttributes");
            }

            if (cnKey != null) {
                msg.addAttribute(cnKey, cnValue, which);
            }
        }
    }
    
    public OneKey BuildKey(CBORObject keyIn, boolean fPublicKey) throws CoseException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, IOException {
        CBORObject cnKeyOut = CBORObject.NewMap();
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
 
        for (CBORObject key : keyIn.getKeys()) {
            CBORObject cnValue = keyIn.get(key);
            
            switch (key.AsString()) {
                case "kty":
                    switch (cnValue.AsString()) {
                        case "EC":
                            cnKeyOut.set(CBORObject.FromObject(1), CBORObject.FromObject(2));
                            break;
                            
                        case "OKP":
                            cnKeyOut.set(CBORObject.FromObject(1), KeyKeys.KeyType_OKP);
                            break;
                            
                        case "oct":
                            cnKeyOut.set(CBORObject.FromObject(1), CBORObject.FromObject(4));
                            break;

                        case "RSA":
                            cnKeyOut.set(CBORObject.FromObject(1), KeyKeys.KeyType_RSA);
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
                                    
                        case "Ed25519":
                            cnValue = KeyKeys.OKP_Ed25519;
                            break;

                        case "Ed448":
                            cnValue = KeyKeys.OKP_Ed448;
                            throw new CoseException("Unsupported Algorithm");
                            // break;

                        case "X25519":
                            cnValue = KeyKeys.OKP_X25519;
                            break;

                        case "X448":
                            cnValue = KeyKeys.OKP_X448;
                            break;
                    }
                    
                            
                    cnKeyOut.set(CBORObject.FromObject(-1), cnValue);
                    break;
                    
                case "x":
                    cnKeyOut.set(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;
                    
                case "x_hex":
                    cnKeyOut.set(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;

                case "y":
                    cnKeyOut.set(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;

                case "y_hex":
                    cnKeyOut.set(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;

                case "d":
                    if (!fPublicKey) {
                        cnKeyOut.set(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    }
                    break;

                case "d_hex":
                    if(keyIn.get("kty").AsString().equals("RSA")) {
                        cnKeyOut.set(KeyKeys.RSA_D.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                        break;
                    }
                    if (!fPublicKey) {
                        cnKeyOut.set(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    }
                    break;

                case "k":
                    cnKeyOut.set(CBORObject.FromObject(-1), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;
                    
                case "k_hex":
                    cnKeyOut.set(CBORObject.FromObject(-1), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                    
                case "kid":
                    cnKeyOut.set(CBORObject.FromObject(KeyKeys.KeyId), CBORObject.FromObject(StandardCharsets.UTF_8.encode(cnValue.AsString()).array()));
                    break;
                    
                case "kid_hex":
                    cnKeyOut.set(CBORObject.FromObject(KeyKeys.KeyId), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                    
                case "pkcs8_b64":
                    byte[] pkcs8 = Base64.getDecoder().decode(cnValue.AsString());
                    
                    privateKey = ImportPKCS8(pkcs8);
                    break;
                    
                case "x509_b64":
                    byte[] x509 = Base64.getDecoder().decode(cnValue.AsString());
                    CertificateFactory factX509 = CertificateFactory.getInstance("X.509");
                    X509Certificate x509Cert = (X509Certificate) factX509.generateCertificate(new ByteArrayInputStream(x509));
                    publicKey = x509Cert.getPublicKey();
                    break;

                case "n_hex":
                    cnKeyOut.set(KeyKeys.RSA_N.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                case "e_hex":
                    cnKeyOut.set(KeyKeys.RSA_E.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                case "p_hex":
                    cnKeyOut.set(KeyKeys.RSA_P.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                case "q_hex":
                    cnKeyOut.set(KeyKeys.RSA_Q.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                case "dP_hex":
                    cnKeyOut.set(KeyKeys.RSA_DP.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                case "dQ_hex":
                    cnKeyOut.set(KeyKeys.RSA_DQ.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
                case "qi_hex":
                    cnKeyOut.set(KeyKeys.RSA_QI.AsCBOR(), CBORObject.FromObject(hexStringToByteArray(cnValue.AsString())));
                    break;
            }
        }
        
        if (publicKey != null || privateKey != null) {
            if (fPublicKey) {
                return new OneKey(publicKey, null);
            }
            return new OneKey(publicKey, privateKey);
        }
        
        return new OneKey( cnKeyOut);
    }
            
    private PrivateKey ImportPKCS8(byte[] pkcs8) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(pkcs8);
        PrivateKey privateKey;

        try {
            KeyFactory fact = KeyFactory.getInstance("EdDSA", new BouncyCastleProvider());
            privateKey = fact.generatePrivate(keyspec);
            return privateKey;
        } 
        catch (Exception e) {
            
        }

        try {
            KeyFactory fact = KeyFactory.getInstance("ECDSA");
            privateKey = fact.generatePrivate(keyspec);
            return privateKey;
        } 
        catch (Exception e) {
            
        }

        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            privateKey = fact.generatePrivate(keyspec);
            return privateKey;
        } 
        catch (NoSuchAlgorithmException e) {
            throw e;
        }
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
         if (old.getType() == CBORType.Integer) {
             return old;
         }

         switch (old.AsString()) {
         case "A128GCM": return AlgorithmID.AES_GCM_128.AsCBOR();
         case "A192GCM": return AlgorithmID.AES_GCM_192.AsCBOR();
         case "A256GCM": return AlgorithmID.AES_GCM_256.AsCBOR();
         case "A128KW": return AlgorithmID.AES_KW_128.AsCBOR();
         case "A192KW": return AlgorithmID.AES_KW_192.AsCBOR();
         case "A256KW": return AlgorithmID.AES_KW_256.AsCBOR();
         // case "RSA-OAEP": return AlgorithmID.RSA_OAEP.AsCBOR();
         // case "RSA-OAEP-256": return AlgorithmID.RSA_OAEP_256.AsCBOR();
         case "HS256": return AlgorithmID.HMAC_SHA_256.AsCBOR();
         case "HS256/64": return AlgorithmID.HMAC_SHA_256_64.AsCBOR();
         case "HS384": return AlgorithmID.HMAC_SHA_384.AsCBOR();
         case "HS512": return AlgorithmID.HMAC_SHA_512.AsCBOR();
         case "ES256": return AlgorithmID.ECDSA_256.AsCBOR();
         case "ES384": return AlgorithmID.ECDSA_384.AsCBOR();
         case "ES512": return AlgorithmID.ECDSA_512.AsCBOR();
         // case "PS256": return AlgorithmID.RSA_PSS_256.AsCBOR();
         // case "PS512": return AlgorithmID.RSA_PSS_512.AsCBOR();
         case "direct": return AlgorithmID.Direct.AsCBOR();
         //case "AES-CMAC-128/64": return AlgorithmID.AES_CMAC_128_64.AsCBOR();
         //case "AES-CMAC-256/64": return AlgorithmID.AES_CMAC_256_64.AsCBOR();
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
         case "HKDF-HMAC-SHA-256": return AlgorithmID.HKDF_HMAC_SHA_256.AsCBOR();
         case "HKDF-HMAC-SHA-512": return AlgorithmID.HKDF_HMAC_SHA_512.AsCBOR();
         case "HKDF-AES-128": return AlgorithmID.HKDF_HMAC_AES_128.AsCBOR();
         case "HKDF-AES-256": return AlgorithmID.HKDF_HMAC_AES_256.AsCBOR();
         case "ECDH-ES": return AlgorithmID.ECDH_ES_HKDF_256.AsCBOR();
         case "ECDH-ES-512": return AlgorithmID.ECDH_ES_HKDF_512.AsCBOR();
         case "ECDH-SS": return AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
         case "ECDH-SS-256": return AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
         case "ECDH-SS-512": return AlgorithmID.ECDH_SS_HKDF_512.AsCBOR();
         case "ECDH-ES+A128KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_128.AsCBOR();
         case "ECDH-SS+A128KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_128.AsCBOR();
         case "ECDH-ES-A128KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_128.AsCBOR();
         case "ECDH-SS-A128KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_128.AsCBOR();
         case "ECDH-ES-A192KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_192.AsCBOR();
         case "ECDH-SS-A192KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_192.AsCBOR();
         case "ECDH-ES-A256KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_256.AsCBOR();
         case "ECDH-SS-A256KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_256.AsCBOR();
         case "EdDSA": return AlgorithmID.EDDSA.AsCBOR();
         case "RSA-PSS-256": return AlgorithmID.RSA_PSS_256.AsCBOR();
         case "RSA-PSS-384": return AlgorithmID.RSA_PSS_384.AsCBOR();
         case "RSA-PSS-512": return AlgorithmID.RSA_PSS_512.AsCBOR();

         default: return old;
         }
     }
    
    static CBORObject HeaderMap(CBORObject obj) {
        switch (obj.AsString()) {
            default:
                return obj;
                
        }
    }

     public boolean HasFailMarker(CBORObject cn) {
        CBORObject cnFail = cn.get("fail");
        if (cnFail != null && cnFail.AsBoolean()) return true;
        return false;
    }
     
    int _ValidateSigned(CBORObject cnControl, byte[] pbEncoded) throws CoseException {
	CBORObject cnInput = cnControl.get("input");
	CBORObject pFail;
	CBORObject cnSign;
	CBORObject cnSigners;
        CBORObject cnCounter;
	SignMessage	hSig = null;
	int type;
	int iSigner;
	boolean fFailBody;

        fFailBody = HasFailMarker(cnControl);
        
        try {
            cnSign = cnInput.get("sign");
            cnSigners = cnSign.get("signers");

            for (iSigner=0; iSigner < cnSigners.size(); iSigner++) {

                try {
                    Message msg = Message.DecodeFromBytes(pbEncoded, MessageTag.Sign);
                    hSig = (SignMessage) msg;
                }
                catch(Exception e) {
                    if (fFailBody) return 0;
                    
                }

                SetReceivingAttributes(hSig, cnSign);

                OneKey cnkey = BuildKey(cnSigners.get(iSigner).get("key"), false);

                Signer hSigner = hSig.getSigner(iSigner);

                SetReceivingAttributes(hSigner, cnSigners.get(iSigner));

                hSigner.setKey(cnkey);

                boolean fFailSigner = HasFailMarker(cnSigners.get(iSigner));

                try {
                    boolean f = hSig.validate(hSigner);
                    if (!f && !(fFailBody || fFailSigner)) CFails++;
                }
                catch (Exception e) {
                    if (!fFailBody && !fFailSigner) CFails++;
                }
                
                cnCounter = cnSigners.get(iSigner).get("countersign0");
                if (cnCounter != null) {
                    CheckCounterSignature0(hSigner, cnCounter);
                }

                cnCounter = cnSigners.get(iSigner).get("countersign");
                if (cnCounter != null) {
                    CheckCounterSignatures(hSigner, cnCounter);
                }
            }
            
            cnCounter = cnSign.get("countersign0");
            if (cnCounter != null) {
                CheckCounterSignature0(hSig, cnCounter);
            }

            cnCounter = cnSign.get("countersign");
            if (cnCounter != null) {
                CheckCounterSignatures(hSig, cnCounter);
            }
        }
        catch (CoseException e) {
            throw e;
        }
        catch (Exception e) {
            System.out.print("... FAIL\nException " + e + "\n");
            CFails++;
        }
        return 0;
    }

    int ValidateSigned(CBORObject cnControl) throws CoseException
    {
        String strExample = cnControl.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);

	return _ValidateSigned(cnControl, rgb);
    }

    int BuildSignedMessage(CBORObject cnControl) throws CoseException
    {
	int iSigner;
        byte[] rgb;
        
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

        if (HasFailMarker(cnControl)) return 0;

        try {
            SignMessage hSignObj = new SignMessage();

            CBORObject cnInputs = cnControl.get("input");
            CBORObject cnSign = cnInputs.get("sign");

            CBORObject cnContent = cnInputs.get("plaintext");
            if (cnContent == null) {
                cnContent = cnInputs.get("plaintext_hex");
                hSignObj.SetContent(hexStringToByteArray(cnContent.AsString()));
            }
            else {
                hSignObj.SetContent(cnContent.AsString());
            }

            SetSendingAttributes(hSignObj, cnSign, false);

            if (cnSign.ContainsKey("countersign0")) {
                AddCounterSignature0(hSignObj, cnSign.get("countersign0"));
            }

            if (cnSign.ContainsKey("countersign")) {
                AddCounterSignature(hSignObj, cnSign.get("countersign"));
            }

            CBORObject cnSigners = cnSign.get("signers");

            for (iSigner = 0; iSigner < cnSigners.size(); iSigner++) {
                OneKey cnkey = BuildKey(cnSigners.get(iSigner).get("key"), false);

                Signer hSigner = new Signer();

                SetSendingAttributes(hSigner, cnSigners.get(iSigner), false);

                hSigner.setKey(cnkey);

                if (cnSigners.get(iSigner).ContainsKey("countersign0")) {
                    AddCounterSignature0(hSigner, cnSigners.get(iSigner).get("countersign0"));
                }

                if (cnSigners.get(iSigner).ContainsKey("countersign")) {
                    AddCounterSignature(hSigner, cnSigners.get(iSigner).get("countersign"));
                }

                hSignObj.AddSigner(hSigner);

            }

            if (cnSign.ContainsKey("countersign0")) {
                AddCounterSignature0(hSignObj, cnSigners.get("countersign0"));
            }

            CBORObject cnCounterSign = cnSign.get("countersign");
            if (cnCounterSign != null) {
                AddCounterSignature(hSignObj, cnCounterSign);
            }

            hSignObj.sign();
            

            rgb = hSignObj.EncodeToBytes();
        }
        catch(Exception e) {
           System.out.print("... Exception " + e + "\n");
             
            CFails++;
            return 0;
        }

	int f = _ValidateSigned(cnControl, rgb);
        return f;
    } 
    
int _ValidateSign0(CBORObject cnControl, byte[] pbEncoded) throws CoseException
{
	CBORObject cnInput = cnControl.get("input");
	CBORObject cnSign;
	Sign1Message	hSig;
	int type;
	boolean fFail;

        try {
            fFail = HasFailMarker(cnControl);

            cnSign = cnInput.get("sign0");

            try {
                Message msg = Message.DecodeFromBytes(pbEncoded, MessageTag.Sign1);
                hSig = (Sign1Message) msg;
            }
            catch (CoseException e) {
                if (!fFail) CFails++;
                return 0;
            }


            SetReceivingAttributes(hSig, cnSign);

            OneKey cnkey = BuildKey(cnSign.get("key"), true);

            boolean fFailInput = HasFailMarker(cnInput);

            try {
                boolean f = hSig.validate(cnkey);
                if (f && (fFail || fFailInput)) CFails++;
                if (!f && !(fFail || fFailInput)) CFails++;
            }
            catch (Exception e) {
                if (!fFail && !fFailInput) CFails++;
            }

            CBORObject cnCounter = cnSign.get("countersign0");
            if (cnCounter != null) {
                CheckCounterSignature0(hSig, cnCounter);
            }

            cnCounter = cnSign.get("countersign");
            if (cnCounter != null) {
                CheckCounterSignatures(hSig, cnCounter);
                }
        }
        catch (CoseException e) {
            throw e;
        }
        catch (Exception e) {
           System.out.print("... Exception " + e + "\n");

           CFails++;
        }
	return 0;
    }

    int ValidateSign0(CBORObject cnControl) throws CoseException  
    {
        String strExample = cnControl.get("output").get("cbor").AsString();
        byte[] rgb =  hexStringToByteArray(strExample);

	return _ValidateSign0(cnControl, rgb);
    }

    int BuildSign0Message(CBORObject cnControl) throws CoseException
    {
        byte[] rgb;
	//
	//  We don't run this for all control sequences - skip those marked fail.
	//

        if (HasFailMarker(cnControl)) return 0;

        try {
            Sign1Message hSignObj = new Sign1Message();

            CBORObject cnInputs = cnControl.get("input");
            CBORObject cnSign = cnInputs.get("sign0");

            CBORObject cnContent = cnInputs.get("plaintext");
            if (cnContent == null) {
                cnContent = cnInputs.get("plaintext_hex");
                hSignObj.SetContent(hexStringToByteArray(cnContent.AsString()));
            }
            else {
                hSignObj.SetContent(cnContent.AsString());
            }

            SetSendingAttributes(hSignObj, cnSign, false);

            if (cnSign.ContainsKey("countersign0")) {
               AddCounterSignature0(hSignObj, cnSign.get("countersign0"));
            }

            if (cnSign.ContainsKey("countersign")) {
                AddCounterSignature(hSignObj, cnSign.get("countersign"));
            }

            OneKey cnkey = BuildKey(cnSign.get("key"), false);

            hSignObj.sign(cnkey);

            rgb = hSignObj.EncodeToBytes();
        }
        catch (Exception e) {
            CFails++;
            return 0;
        }

	int f = _ValidateSign0(cnControl, rgb);
        return 0;
    }
    
    void AddCounterSignature0(Message msg, CBORObject cSigInfo) throws CoseException, Exception
    {
        if (cSigInfo.getType() == CBORType.Map) {
            if ((!cSigInfo.ContainsKey("signers") || (cSigInfo.get("signers").getType() != CBORType.Array) ||
                 (cSigInfo.get("signers").getValues().size() != 1))) {
                throw new CoseException("Invalid input file");
            }

            CBORObject cSigner = cSigInfo.get("signers").get(0);
            OneKey cnkey = BuildKey(cSigner.get("key"), false);

            CounterSign1 hSigner = new CounterSign1();

            SetSendingAttributes(hSigner, cSigner, false);
            
            

            hSigner.setKey(cnkey);

            msg.setCountersign1(hSigner);
        }
        else {
            throw new CoseException("Invalid input file");
        }
    }

    void AddCounterSignature0(Signer msg, CBORObject cSigInfo) throws CoseException, Exception
    {
        if (cSigInfo.getType() == CBORType.Map) {
            if ((!cSigInfo.ContainsKey("signers") || (cSigInfo.get("signers").getType() != CBORType.Array) ||
                 (cSigInfo.get("signers").getValues().size() != 1))) {
                throw new CoseException("Invalid input file");
            }

            CBORObject cSigner = cSigInfo.get("signers").get(0);
            OneKey cnkey = BuildKey(cSigner.get("key"), false);

            CounterSign1 hSigner = new CounterSign1();

            SetSendingAttributes(hSigner, cSigner, false);

            hSigner.setKey(cnkey);

            msg.setCountersign1(hSigner);
        }
        else {
            throw new CoseException("Invalid input file");
        }
    }

    void AddCounterSignature(Message msg, CBORObject cSigInfo) throws CoseException, Exception
    {
        if ((cSigInfo.getType() != CBORType.Map) || !cSigInfo.ContainsKey("signers") ||
            (cSigInfo.get("signers").getType() != CBORType.Array)) {
            throw new CoseException("invalid input file");
        }

        for (CBORObject signer : cSigInfo.get("signers").getValues()) {
            OneKey cnKey = BuildKey(signer.get("key"), false);

            CounterSign hSigner = new CounterSign();

            SetSendingAttributes(hSigner, signer, false);

            hSigner.setKey(cnKey);

            msg.addCountersignature(hSigner);

        }
    }

    void AddCounterSignature(Signer msg, CBORObject cSigInfo) throws CoseException, Exception
    {
        if ((cSigInfo.getType() != CBORType.Map) || !cSigInfo.ContainsKey("signers") ||
            (cSigInfo.get("signers").getType() != CBORType.Array)) {
            throw new CoseException("invalid input file");
        }

        for (CBORObject signer : cSigInfo.get("signers").getValues()) {
            OneKey cnKey = BuildKey(signer.get("key"), false);

            CounterSign hSigner = new CounterSign();

            SetSendingAttributes(hSigner, signer, false);

            hSigner.setKey(cnKey);

            msg.addCountersignature(hSigner);
        }
    }
    
    void CheckCounterSignatures(Message msg, CBORObject cSigInfo)
    {
        try {
            CBORObject cSigs = msg.findAttribute(HeaderKeys.CounterSignature);
            if (cSigs == null) {
                CFails++;
                return;
            }

            if (cSigs.getType() != CBORType.Array) {
                CFails++;
                return;
            }

            CBORObject cSigConfig = cSigInfo.get("signers");
            if ((cSigConfig.getValues().size() > 1) && 
                    (cSigs.getValues().size() != msg.getCountersignerList().size())) {
                CFails++;
                return;
            }

            int iCSign;
            for (iCSign = 0; iCSign < cSigConfig.getValues().size(); iCSign++) {
                CounterSign sig = msg.getCountersignerList().get(iCSign);

                OneKey cnKey = BuildKey(cSigConfig.get(iCSign).get("key"), true);
                SetReceivingAttributes(sig, cSigConfig.get(iCSign));

                sig.setKey(cnKey);

                try {
                    Boolean f = msg.validate(sig);
                    if (!f) CFails++;
                }
                catch (Exception e) {
                    CFails++;
                }
            }
        }
        catch (Exception e) {
            CFails++;
        }
    }

    void CheckCounterSignatures(Signer msg, CBORObject cSigInfo)
    {
        try {
            CBORObject cSigs = msg.findAttribute(HeaderKeys.CounterSignature);
            if (cSigs == null) {
                CFails++;
                return;
            }

            if (cSigs.getType() != CBORType.Array) {
                CFails++;
                return;
            }

            CBORObject cSigConfig = cSigInfo.get("signers");
            if ((cSigConfig.getValues().size() > 1) && 
                    (cSigs.getValues().size() != msg.getCountersignerList().size())) {
                CFails++;
                return;
            }

            int iCSign;
            for (iCSign = 0; iCSign < cSigConfig.getValues().size(); iCSign++) {
                CounterSign sig = msg.getCountersignerList().get(iCSign);

                OneKey cnKey = BuildKey(cSigConfig.get(iCSign).get("key"), true);
                SetReceivingAttributes(sig, cSigConfig.get(iCSign));

                sig.setKey(cnKey);

                try {
                    Boolean f = msg.validate(sig);
                    if (!f) CFails++;
                }
                catch (Exception e) {
                    CFails++;
                }
            }
        }
        catch (Exception e) {
            CFails++;
        }
    }

    void CheckCounterSignature0(Message msg, CBORObject cSigInfo)
    {
        try {
            CBORObject cSigs = msg.findAttribute(HeaderKeys.CounterSignature0);

            if (cSigs == null) {
                CFails++;
                return;
            }

            if (cSigs.getType() != CBORType.ByteString) {
                CFails++;
                return;
            }

            CBORObject cSigConfig = cSigInfo.get("signers");
            if (1 != cSigConfig.getValues().size()) {
                CFails++;
                return;
            }

            CounterSign1 sig = msg.getCountersign1();

            SetReceivingAttributes(sig, cSigConfig.get(0));

            OneKey cnKey = BuildKey(cSigConfig.get(0).get("key"), true);
            sig.setKey(cnKey);

            try {
                Boolean f = msg.validate(sig);
                if (!f) {
                    throw new Exception("Failed countersignature validation");
                }
            }
            catch (Exception e) {
                throw new Exception("Failed countersignature validation");
            }
        }
        catch (Exception e) {
            CFails++;
        }
    }

    void CheckCounterSignature0(Signer msg, CBORObject cSigInfo)
    {
        try {
            CBORObject cSigs = msg.findAttribute(HeaderKeys.CounterSignature0);

            if (cSigs == null) {
                CFails++;
                return;
            }

            if (cSigs.getType() != CBORType.ByteString) {
                CFails++;
                return;
            }

            CBORObject cSigConfig = cSigInfo.get("signers");
            if (1 != cSigConfig.getValues().size()) {
                CFails++;
                return;
            }

            CounterSign1 sig = msg.getCountersign1();

            SetReceivingAttributes(sig, cSigConfig.get(0));

            OneKey cnKey = BuildKey(cSigConfig.get(0).get("key"), true);
            sig.setKey(cnKey);

            try {
                Boolean f = msg.validate(sig);
                if (!f) {
                    throw new Exception("Failed countersignature validation");
                }
            }
            catch (Exception e) {
                throw new Exception("Failed countersignature validation");
            }
        }
        catch (Exception e) {
            CFails++;
        }
    }    
 }
