/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import static COSE.MAC0MessageTest.rgbContent;
import com.upokecenter.cbor.CBORObject;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class MAC0MessageTest extends TestBase {
    static byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};
 
    CBORObject cnKey256;

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    public MAC0MessageTest() {
    }
        
    @Before
    public void setUp() {
        cnKey256 = CBORObject.NewMap();
        cnKey256.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        cnKey256.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(rgbKey256));
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */

    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        MAC0Message msg = new MAC0Message();
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.Create(rgbKey256);
        
        byte[] rgbMsg = msg.EncodeToBytes();
        
        msg = (MAC0Message) Message.DecodeFromBytes(rgbMsg, MessageTag.MAC0);
        boolean contentNew = msg.Validate(rgbKey256);
        assertTrue(contentNew);
    }
    
    @Test
    public void macNoAlgorithm() throws CoseException, Exception {
        MAC0Message msg = new MAC0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Algorithm Specified");
        msg.SetContent(rgbContent);
        msg.Create(rgbKey256);
    }    

    @Test
    public void macUnknownAlgorithm() throws CoseException, Exception {
        MAC0Message msg = new MAC0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unknown Algorithm Specified");
        msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.Create(rgbKey256);
    }    

    @Test
    public void macUnsupportedAlgorithm() throws CoseException, Exception {
        MAC0Message msg = new MAC0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unsupported MAC Algorithm");
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_256.AsCBOR(), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.Create(rgbKey256);
    }    

    @Test
    public void macNoContent() throws CoseException, Exception {
        MAC0Message msg = new MAC0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Content Specified");
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
        msg.Create(rgbKey256);
    }    
    
    @Test
    public void macDecodeWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Message is not a COSE security Message");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }

    @Test
    public void macDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }

    @Test
    public void macDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }

    @Test
    public void macDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }

    @Test
    public void macDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }

    @Test
    public void macDecodeBadContent() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }

    @Test
    public void macDecodeBadRecipients() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid MAC0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.MAC0);        
    }
    
}
