/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.rules.ExpectedException;

/**
 *
 * @author jimsch
 */
public class Encrypt0MessageTest {
    byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    byte[] rgbKey256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    byte[] rgbContent = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n', 't'};
    byte[] rgbIV128 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    
    public Encrypt0MessageTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Test of decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testRoundTrip() throws Exception {
        System.out.println("Round Trip");
        Encrypt0Message msg = new Encrypt0Message();
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.AddProtected(HeaderKeys.IV, CBORObject.FromObject(rgbIV96));
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        byte[] rgbMsg = msg.EncodeToBytes();
        
        msg = (Encrypt0Message) Message.DecodeFromBytes(rgbMsg, MessageTag.Encrypt0);
        byte[] contentNew = msg.decrypt(rgbKey128);
      
        assertArrayEquals(rgbContent, contentNew);
    }
    
    @Test
    public void encryptNoAlgorithm() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Algorithm Specified");
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
    }    

    @Test
    public void encryptUnknownAlgorithm() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unknown Algorithm Specified");
        msg.AddProtected(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"));
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
    }    

    @Test
    public void encryptUnsupportedAlgorithm() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Unsupported Algorithm Specified");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR());
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
    }    

    @Test
    public void encryptIncorrectKeySize() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Incorrect Key Size");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey256);
    }    

    @Test
    public void encryptNullKey() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(NullPointerException.class);
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.SetContent(rgbContent);
        msg.encrypt(null);
    }    

    @Test
    public void encryptNoContent() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("No Content Specified");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.encrypt(rgbKey128);
    }    

    @Test
    public void encryptBadIV() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("IV is incorrectly formed");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.AddUnprotected(HeaderKeys.IV, CBORObject.FromObject("IV"));
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
    }    

    @Test
    public void encryptIncorrectIV() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("IV size is incorrect");
        msg.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        msg.AddUnprotected(HeaderKeys.IV, rgbIV128);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
    }    
    
    @Test
    public void encryptNoTag() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message(false, true);

        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(),Message.ProtectedAttributes);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Message.ProtectedAttributes);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        CBORObject cn = msg.EncodeCBORObject();
        
        assert(!cn.isTrue());
    }
    
    @Test
    public void encryptNoEmitContent() throws CoseException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message(true, false);

        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(),Message.ProtectedAttributes);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Message.UnprotectedAttributes);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        CBORObject cn = msg.EncodeCBORObject();
        
        assert(cn.get(2).isNull());
    }
    
    @Test
    public void noContentForDecrypt() throws CoseException, IllegalStateException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message(true, false);

        thrown.expect(CoseException.class);
        thrown.expectMessage("No Encrypted Content Specified");
        
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Message.ProtectedAttributes);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Message.UnprotectedAttributes);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        
        byte[] rgb = msg.EncodeToBytes();
        
        msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
        msg.decrypt(rgbKey128);
        
    }
    
    @Test
    public void roundTripDetached() throws CoseException, IllegalStateException, InvalidCipherTextException {
        Encrypt0Message msg = new Encrypt0Message(true, false);
        
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Message.ProtectedAttributes);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Message.UnprotectedAttributes);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        
        byte[] content = msg.getEncryptedContent();
        
        byte[] rgb = msg.EncodeToBytes();
        
        msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
        msg.setEncryptedContent(content);
        msg.decrypt(rgbKey128);
        
    }    
    
    @Test
    public void encryptWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Message is not a COSE security Message");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }

    @Test
    public void encryptDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }

    @Test
    public void encryptDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }

    @Test
    public void encryptDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }

    @Test
    public void encryptDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }

    @Test
    public void encryptDecodeBadContent() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }

    @Test
    public void encryptDecodeBadTag() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Encrypt0 structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Encrypt0);        
    }
}
