/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.rules.*;

/**
 *
 * @author jimsch
 */
public class SignWikiTest extends TestBase {
    static OneKey signingKey;
    static OneKey sign2Key;
    static OneKey sign3Key;
    
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    @Before
    public void setUp() throws CoseException {
        signingKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        sign2Key = OneKey.generateKey(AlgorithmID.ECDSA_512);
        sign3Key = OneKey.generateKey(AlgorithmID.ECDSA_384);
    }
    
    @Test
    public void testSignAMessage() throws CoseException {
        byte[] result = SignAMessage("This is lots of content");
        assert( VerifyAMessage(result, signingKey) );
    }
    
    public static byte[] SignAMessage(String ContentToSign) throws CoseException {
        
    //  Create the signed message
    SignMessage msg = new SignMessage();
    
    //  Add the content to the message
    msg.SetContent(ContentToSign);
    
    //  Create the signer for the message
    Signer signer = new Signer();
    signer.setKey(signingKey);
    signer.addAttribute(HeaderKeys.Algorithm, signingKey.get(KeyKeys.Algorithm), Attribute.PROTECTED);
    CBORObject o = signingKey.get(KeyKeys.KeyId);
    if (o != null) signer.addAttribute(HeaderKeys.KID, o, Attribute.UNPROTECTED);

    msg.AddSigner(signer);

    //  Force the message to be signed
    msg.sign();

    //  Now serialize out the message
    return msg.EncodeToBytes();
    }
    
    public static boolean VerifyAMessage(byte[] message, OneKey key) {
        boolean result;
        
        try {
            SignMessage msg = (SignMessage) Message.DecodeFromBytes(message);
            Signer signer = msg.getSigner((0));
            signer.setKey(key);
          
            result = msg.validate(signer);
        } catch (CoseException e) {
            return false;
        }
        
        return result;
    }

    @Test
    public void testMultiSignMessage() throws CoseException {
        OneKey[] keys = new OneKey[3];
        keys[0] = signingKey;
        keys[1] = sign3Key;
        keys[2] = sign2Key;
        
        KeySet keyset = new KeySet();
        keyset.add(signingKey);
        keyset.add(sign2Key);
        keyset.add(sign3Key);
        
        byte[] result = MultiSignMessage("This is lots of content", keys);
        assert(MultiValidateSignedMessage(result, keyset, true));
        assert(MultiValidateSignedMessage(result, keyset, false));
        
        keyset.remove(sign3Key);
        assert(!MultiValidateSignedMessage(result, keyset, true));
    }
    
    public static byte[] MultiSignMessage(String ContentToSign, OneKey[] keys) throws CoseException {
        //  Create the signed message
        SignMessage msg = new SignMessage();

        //  Add the content to the message
        msg.SetContent(ContentToSign);

        for (OneKey key : keys) {
            //  Create the signer for the message
            Signer signer = new Signer();
            signer.setKey(key);
            signer.addAttribute(HeaderKeys.Algorithm, key.get(KeyKeys.Algorithm), Attribute.PROTECTED);
            CBORObject o = key.get(KeyKeys.KeyId);
            if (o != null) signer.addAttribute(HeaderKeys.KID, o, Attribute.UNPROTECTED);

            msg.AddSigner(signer);
        }

        //  Force the message to be signed
        msg.sign();

        //  Now serialize out the message
        return msg.EncodeToBytes();
        
    }
    
    public static boolean MultiValidateSignedMessage(byte[] message, KeySet keys, boolean needAllToPass) {
        boolean returnValue = false;
        try {
            //  Decode the message
            SignMessage msg = (SignMessage) Message.DecodeFromBytes(message);
            
            //  Enumerate through all of the signers
            
            for (Signer s : msg.getSignerList()) {
                boolean fSignerValidates = false;
            
                //  Look for the key identifier and algorithm for the signer
                
                CBORObject kid = s.findAttribute(HeaderKeys.KID);
                CBORObject alg = s.findAttribute(HeaderKeys.Algorithm);
                
                //  Create two lists of keys
                //   Those that have a matching kid value
                //   Those that either do not match or do not have a kid value
               
                List<OneKey> keysWithKid = new ArrayList<OneKey>();
                List<OneKey> keysWithoutKid = new ArrayList<OneKey>();
                
                for (OneKey k : keys.getList()) {
                    
                    //  If the key has an algorithm, it must match the one used in the signature
                    
                    CBORObject keyAlg = k.get(KeyKeys.Algorithm);
                    if ((keyAlg != null) && !keyAlg.equals(alg)) continue;
                    
                    // If the key has a key_ops field, then it must allow signature verification
                  
                    CBORObject ops = k.get(KeyKeys.Key_Ops);
                    if (ops != null) {
                        if (ops.getType() == CBORType.Number) {
                            if (ops.AsInt32() != 2) continue;
                        } 
                        else if (ops.getType() == CBORType.Array) {
                            boolean found = false;
                            for (int i=0; i<ops.size(); i++) {
                                if ((ops.get(i).getType() == CBORType.Number) && (ops.get(i).AsInt32() == 2)) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) continue;
                        }
                        else continue;
                    }
                    
                    //  Compare the key ids and divide into two lists
                    
                    CBORObject o = k.get(KeyKeys.KeyId);
                    if (o != null) {
                        if (kid.equals(o)) {
                            keysWithKid.add(k);
                        }
                        else {
                            //  Some implementations will require kid matches 
                            //  In which case this line should be removed
                            keysWithoutKid.add(k);
                        }
                    }
                    else keysWithoutKid.add(k);
                }
                
                //  Check kid matches first as the list should be short
                
                for (OneKey k : keysWithKid) {
                    s.setKey(k);
          
                    try {
                        boolean result = msg.validate(s);
                        if (result) {
                            fSignerValidates = true;
                            s.clearKey();
                            break;
                        }
                    }
                    catch (CoseException e) {
                    }
                    s.clearKey ();
                }
                
                //  If we did not validate the signature, try the keys w/o a kid
                
                if (!fSignerValidates) {
                    for (OneKey k : keysWithoutKid) {
                        s.setKey(k);

                        try {
                            boolean result = msg.validate(s);
                            if (result) {
                                fSignerValidates = true;
                                s.clearKey();
                                break;
                            }
                        }
                        catch (CoseException e) {
                        }
                        s.clearKey();
                    }                    
                }
                
                //  If we need all signatures to validate then we can return failure
                
                if (needAllToPass) {
                    if (!fSignerValidates) return false;
                }
                //  If we need only one to pass then we can return success
                else if (fSignerValidates) return true;
            }
        } catch (CoseException e) {
            return false;
        }
        //  If this is true, then we did not return false because one signature failed.
        //  If this is false, then we never found a successful signture
        return needAllToPass;
    }
}
