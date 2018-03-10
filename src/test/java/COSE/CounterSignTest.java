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
public class CounterSignTest extends TestBase {
    
    public CounterSignTest() {
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

   @Test
    public void signerDecodeWrongBasis() throws CoseException {
        CBORObject obj = CBORObject.NewMap();
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        byte[] rgb = obj.EncodeToBytes();
        CounterSign sig = new CounterSign();
        sig.DecodeFromBytes(rgb);        
    }

    @Test
    public void signerDecodeWrongCount() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        byte[] rgb = obj.EncodeToBytes();
        CounterSign sig = new CounterSign();
        sig.DecodeFromBytes(rgb);        
    }

    @Test
    public void signerDecodeBadProtected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        byte[] rgb = obj.EncodeToBytes();
        CounterSign sig = new CounterSign();
        sig.DecodeFromBytes(rgb);        
    }

    @Test
    public void signerDecodeBadProtected2() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.False));
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        byte[] rgb = obj.EncodeToBytes();
        CounterSign sig = new CounterSign();
        sig.DecodeFromBytes(rgb);        
    }

    @Test
    public void signerDecodeBadUnprotected() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.False);
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        byte[] rgb = obj.EncodeToBytes();
        CounterSign sig = new CounterSign();
        sig.DecodeFromBytes(rgb);        
    }

    @Test
    public void signerDecodeBadSignature() throws CoseException {
        CBORObject obj = CBORObject.NewArray();
        obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
        obj.Add(CBORObject.NewMap());
        obj.Add(CBORObject.False);
        
        thrown.expect(CoseException.class);
        thrown.expectMessage("Invalid Signer structure");

        byte[] rgb = obj.EncodeToBytes();
        CounterSign sig = new CounterSign();
        sig.DecodeFromBytes(rgb);        
    }
    
}
