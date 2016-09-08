/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import java.util.List;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class MACMessageTest {
    static byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};
 
    Recipient recipient256;
    CBORObject cnKey256;

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    public MACMessageTest() {
    }
    
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() throws CoseException {
        recipient256 = new Recipient();
        recipient256.addAttribute(HeaderKeys.Algorithm, AlgorithmID.Direct.AsCBOR(), Attribute.UnprotectedAttributes);
        cnKey256 = CBORObject.NewMap();
        cnKey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        cnKey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey256));
        recipient256.SetKey(cnKey256);        
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of addRecipient method, of class MACMessage.
     */
    @Test
    public void testAddRecipient() {
        System.out.println("addRecipient");
        Recipient recipient = null;
        MACMessage instance = new MACMessage();
        instance.addRecipient(recipient);
    }

    /**
     * Test of getRecipient method, of class MACMessage.
     */
    @Test
    public void testGetRecipient_1args_1() {
        System.out.println("getRecipient");
        int iRecipient = 0;
        MACMessage instance = new MACMessage();
        Recipient expResult = new Recipient();
        instance.addRecipient(expResult);
        Recipient result = instance.getRecipient(iRecipient);
        assertEquals(expResult, result);
    }

    @Test
    public void testGetRecipientCount() {
       MACMessage msg = new MACMessage();
       
       assertEquals(msg.getRecipientCount(), 0);
       
       Recipient r = new Recipient();
       msg.addRecipient(r);
       assertEquals(msg.getRecipientCount(), 1);
    }
    
    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        MACMessage msg = new MACMessage();
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR());
        msg.SetContent(rgbContent);
        msg.addRecipient(recipient256);
        msg.Create();
        
        byte[] rgbMsg = msg.EncodeToBytes();
        
        msg = (MACMessage) Message.DecodeFromBytes(rgbMsg, MessageTag.MAC);
        Recipient r = msg.getRecipient(0);
        r.SetKey(cnKey256);
        boolean contentNew = msg.Validate(r);
        assertTrue(contentNew);
    }

    @Test
    public void macNoRecipients() throws CoseException, InvalidCipherTextException, Exception {
        MACMessage msg = new MACMessage();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No recipients supplied");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR());
        msg.SetContent(rgbContent);
        msg.Create();
    }    
    
    @Test
    public void macNoAlgorithm() throws CoseException, InvalidCipherTextException, Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Algorithm Specified");
        msg.SetContent(rgbContent);
        msg.Create();
    }    

    @Test
    public void macUnknownAlgorithm() throws CoseException, InvalidCipherTextException, Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unknown Algorithm Specified");
        msg.AddProtected(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"));
        msg.SetContent(rgbContent);
        msg.Create();
    }    

    @Test
    public void macUnsupportedAlgorithm() throws CoseException, InvalidCipherTextException, Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unsupported MAC Algorithm");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_256.AsCBOR());
        msg.SetContent(rgbContent);
        msg.Create();
    }    

    @Test
    public void macNoContent() throws CoseException, InvalidCipherTextException, Exception {
        MACMessage msg = new MACMessage();
        msg.addRecipient(recipient256);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Content Specified");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR());
        msg.Create();
    }    
    
    @Test
    public void macDecodeWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Message is not a COSE security Message");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeBadContent() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeBadTag() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.FromObject(rgbContent));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }

    @Test
    public void macDecodeBadRecipients() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.FromObject(rgbContent));
        obj.Add(CBORObject.FromObject(rgbContent));
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC);        
    }
    
}
