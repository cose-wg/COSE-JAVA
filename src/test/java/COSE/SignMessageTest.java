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

import org.junit.*;
import org.junit.rules.ExpectedException;


/**
 *
 * @author jimsch
 */
public class SignMessageTest extends TestBase {
    
    public SignMessageTest() {
    }

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
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
     * Test of EncodeCBORObject method, of class SignMessage.
     */
    @Ignore
    @Test
    public void testEncodeCBORObject() throws Exception {
        System.out.println("EncodeCBORObject");
        SignMessage instance = new SignMessage();
        CBORObject expResult = null;
        CBORObject result = instance.EncodeCBORObject();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getSigner method, of class SignMessage.
     */
    @Ignore
    @Test
    public void testGetSigner() {
        System.out.println("getSigner");
        int iSigner = 0;
        SignMessage instance = new SignMessage();
        Signer expResult = null;
        Signer result = instance.getSigner(iSigner);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    @Test
    public void testGetSignerCount() {
       SignMessage msg = new SignMessage();
       
       assertEquals(msg.getSignerCount(), 0);
       
       Signer r = new Signer();
       msg.AddSigner(r);
       assertEquals(msg.getSignerCount(), 1);
    }

    /**
     * Test of sign method, of class SignMessage.
     */
    @Ignore
    @Test
    public void testSign() throws CoseException {
        System.out.println("sign");
        SignMessage instance = new SignMessage();
        instance.sign();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of validate method, of class SignMessage.
     */
    @Ignore
    @Test
    public void testValidate() throws CoseException {
        System.out.println("validate");
        Signer signerToUse = null;
        SignMessage instance = new SignMessage();
        boolean expResult = false;
        boolean result = instance.validate(signerToUse);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
    
    @Test
    public void signDecodeWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Message is not a COSE security Message");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }

    @Test
    public void signDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid SignMessage structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }

    @Test
    public void signDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid SignMessage structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }

    @Test
    public void signDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid SignMessage structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }

    @Test
    public void signDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid SignMessage structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }

    @Test
    public void signDecodeBadContent() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid SignMessage structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }

    @Test
    public void signDecodeBadRecipients() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(new byte[0]);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid SignMessage structure");

        byte[] rgb = obj.EncodeToBytes();
        Message msg = Message.DecodeFromBytes(rgb, MessageTag.Sign);        
    }
    
}
