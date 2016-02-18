/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.*;
import static org.junit.Assert.assertArrayEquals;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class EncryptMessageTest {
    static byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};
    static byte[] rgbIV128 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    static byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    
    Recipient recipient128;
    CBORObject cnKey128;

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Before
    public void setUp() {
        recipient128 = new Recipient();
        recipient128.addAttribute(HeaderKeys.Algorithm, AlgorithmID.Direct.AsCBOR(), Attribute.UnprotectedAttributes);
        cnKey128 = CBORObject.NewMap();
        cnKey128.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        cnKey128.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey128));
        recipient128.SetKey(cnKey128);        
    }
    
    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        EncryptMessage msg = new EncryptMessage();
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.AddProtected(HeaderKeys.IV, CBORObject.FromObject(rgbIV96));
        msg.SetContent(rgbContent);
        msg.addRecipient(recipient128);
        msg.encrypt();
        
        byte[] rgbMsg = msg.EncodeToBytes();
        
        msg = (EncryptMessage) Message.DecodeFromBytes(rgbMsg, 992);
        Recipient r = msg.getRecipient(0);
        r.SetKey(cnKey128);
        byte[] contentNew = msg.decrypt(r);
        
      
        assertArrayEquals(rgbContent, contentNew);
    }

    @Test
    public void encryptNoRecipients() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No recipients supplied");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.SetContent(rgbContent);
        msg.encrypt();
    }    
    
    @Test
    public void encryptNoAlgorithm() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Algorithm Specified");
        msg.SetContent(rgbContent);
        msg.encrypt();
    }    

    @Test
    public void encryptUnknownAlgorithm() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unknown Algorithm Specified");
        msg.AddProtected(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"));
        msg.SetContent(rgbContent);
        msg.encrypt();
    }    

    @Test
    public void encryptUnsupportedAlgorithm() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unsupported Algorithm Specified");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR());
        msg.SetContent(rgbContent);
        msg.encrypt();
    }    

    @Test
    public void encryptNoContent() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Content Specified");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.encrypt();
    }    

    @Test
    public void encryptBadIV() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("IV is incorrectly formed");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.AddUnprotected(HeaderKeys.IV, CBORObject.FromObject("IV"));
        msg.SetContent(rgbContent);
        msg.encrypt();
    }    

    @Test
    public void encryptIncorrectIV() throws CoseException, InvalidCipherTextException, Exception {
        EncryptMessage msg = new EncryptMessage();
        msg.addRecipient(recipient128);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("IV size is incorrect");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.AddUnprotected(HeaderKeys.IV, rgbIV128);
        msg.SetContent(rgbContent);
        msg.encrypt();
    }    
    
    @Test
    public void encryptDecodeWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Message is not a COSE security Message");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }

    @Test
    public void encryptDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }

    @Test
    public void encryptDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }

    @Test
    public void encryptDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }

    @Test
    public void encryptDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }

    @Test
    public void encryptDecodeBadContent() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }

    @Test
    public void encryptDecodeBadRecipients() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, 992);        
    }
}
