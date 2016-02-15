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

/**
 *
 * @author jimsch
 */
public class Encrypt0MessageTest {
    
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

    /**
     * Test of DecodeFromCBORObject method, of class Encrypt0Message.
     */
    @Test
    public void testDecodeFromCBORObject() throws Exception {
        System.out.println("DecodeFromCBORObject");
        CBORObject obj = null;
        Encrypt0Message instance = new Encrypt0Message();
        instance.DecodeFromCBORObject(obj);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of EncodeToCBORObject method, of class Encrypt0Message.
     */
    @Test
    public void testEncodeToCBORObject() throws Exception {
        System.out.println("EncodeToCBORObject");
        Encrypt0Message instance = new Encrypt0Message();
        
        byte[] rgbContent = {'T', 'h', 'i', 's', ' '};
        byte[] rgbSecret = new byte[128/8];
        rgbSecret[0] = 'a';
        rgbSecret[1] = 'b';
        rgbSecret[3] = 'c';
        
        
        instance.SetContent(rgbContent);
        instance.AddProtected(HeaderKeys.Algorithm, AlgorithmID.AES_GCM_128.AsCBOR());
        instance.Encrypt(rgbSecret);
        CBORObject objOut = instance.EncodeToCBORObject();
        
        CBORObject expResult = null;
        CBORObject result = instance.EncodeToCBORObject();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of Decrypt method, of class Encrypt0Message.
     */
    @Test
    public void testDecrypt() throws Exception {
        System.out.println("Decrypt");
        byte[] rgbKey = null;
        Encrypt0Message instance = new Encrypt0Message();
        byte[] expResult = null;
        byte[] result = instance.Decrypt(rgbKey);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of Encrypt method, of class Encrypt0Message.
     */
    @Test
    public void testEncrypt() throws Exception {
        System.out.println("Encrypt");
        byte[] rgbKey = null;
        Encrypt0Message instance = new Encrypt0Message();
        instance.Encrypt(rgbKey);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
}
