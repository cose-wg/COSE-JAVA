/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import org.junit.*;
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
public class SignerTest extends TestBase {
    
    public SignerTest() {
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
     * Test of setKey method, of class Signer.
     */
    @Ignore
    @Test
    public void testSetKey() throws CoseException {
        System.out.println("setKey");
        OneKey cnKey = null;
        Signer instance = new Signer();
        instance.setKey(cnKey);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

   @Test
    public void signerDecodeWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        Signer sig = new Signer();
        sig.DecodeFromCBORObject(obj);        
    }

    @Test
    public void signerDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        Signer sig = new Signer();
        sig.DecodeFromCBORObject(obj);        
    }

    @Test
    public void signerDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        Signer sig = new Signer();
        sig.DecodeFromCBORObject(obj);        
    }

    @Test
    public void signerDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        Signer sig = new Signer();
        sig.DecodeFromCBORObject(obj);        
    }

    @Test
    public void signerDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        Signer sig = new Signer();
        sig.DecodeFromCBORObject(obj);        
    }

    @Test
    public void signerDecodeBadSignature() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        Signer sig = new Signer();
        sig.DecodeFromCBORObject(obj);        
    }
    
}
