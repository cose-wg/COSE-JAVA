/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
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
public class MessageTest extends TestBase {
    byte[] rgbKey128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    byte[] rgbContent = new byte[]{1,2,3,4,5,6,7};
    byte[] rgbIV96 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    public MessageTest() {
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

    /**
     * Test of DecodeFromBytes method, of class Message.
     */
    @Test
    public void testDecodeUnknown() throws Exception {
        Encrypt0Message msg = new Encrypt0Message(false, true);
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        byte[] rgbMsg = msg.EncodeToBytes();
        
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Message was not tagged and no default tagging option given");

        msg = (Encrypt0Message) Message.DecodeFromBytes(rgbMsg, MessageTag.Unknown);
    }

    /**
     * Test of DecodeFromBytes method, of class Message.
     */
    @Test
    public void testDecodeFromBytes_byteArr_MessageTag() throws Exception {
        Encrypt0Message msg = new Encrypt0Message(true, false);
        msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR(), Attribute.PROTECTED);
        msg.addAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attribute.PROTECTED);
        msg.SetContent(rgbContent);
        msg.encrypt(rgbKey128);
        byte[] rgbMsg = msg.EncodeToBytes();
        
        msg = (Encrypt0Message) Message.DecodeFromBytes(rgbMsg);
        assertEquals(false, msg.HasContent());
    }

    /**
     * Test of HasContent method, of class Message.
     */
    @Test
    public void testHasContent() {
        System.out.println("HasContent");
        Message instance = new Encrypt0Message();
        boolean expResult = false;
        boolean result = instance.HasContent();
        assertEquals(expResult, result);
        
        instance.SetContent(new byte[10]);
        result = instance.HasContent();
        assertEquals(true, result);
    }

    /**
     * Test of SetContent method, of class Message.
     */
    @Test
    public void testSetContent_byteArr() {
        System.out.println("SetContent");
        byte[] rgbData = new byte[]{1,2,3,4,5,6,7};
        Message instance = new Encrypt0Message();
        instance.SetContent(rgbData);
        
        byte[] result = instance.GetContent();
        assertArrayEquals(result, rgbData);
    }

    /**
     * Test of SetContent method, of class Message.
     */
    @Test
    public void testSetContent_String() {
        System.out.println("SetContent");
        String strData = "12345678";
        byte[] rgbData = new byte[]{49, 50, 51, 52, 53, 54, 55, 56};
        
        Message instance = new Encrypt0Message();
        instance.SetContent(strData);
        byte[] result = instance.GetContent();
        assertArrayEquals(result, rgbData);
    }    
}
