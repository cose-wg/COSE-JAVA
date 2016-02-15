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
public class MAC0MessageTest {
    
    public MAC0MessageTest() {
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
     * Test of DecodeFromCBORObject method, of class MAC0Message.
     */
    @Test
    public void testDecodeFromCBORObject() throws Exception {
        System.out.println("DecodeFromCBORObject");
        CBORObject obj = null;
        MAC0Message instance = new MAC0Message();
        instance.DecodeFromCBORObject(obj);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of Validate method, of class MAC0Message.
     */
    @Test
    public void testValidate() throws Exception {
        System.out.println("Validate");
        byte[] rgbKey = null;
        MAC0Message instance = new MAC0Message();
        boolean expResult = false;
        boolean result = instance.Validate(rgbKey);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
}
