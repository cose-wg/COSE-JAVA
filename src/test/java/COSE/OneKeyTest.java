/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Assert;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author jimsch
 */
public class OneKeyTest extends TestBase {
    
    public OneKeyTest() {
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
     * Test of add method, of class OneKey.
     */
    @Ignore
    @Test
    public void testAdd_KeyKeys_CBORObject() {
        System.out.println("add");
        KeyKeys keyValue = null;
        CBORObject value = null;
        OneKey instance = new OneKey();
        instance.add(keyValue, value);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of add method, of class OneKey.
     */
    @Ignore
    @Test
    public void testAdd_CBORObject_CBORObject() {
        System.out.println("add");
        CBORObject keyValue = null;
        CBORObject value = null;
        OneKey instance = new OneKey();
        instance.add(keyValue, value);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of get method, of class OneKey.
     */
    @Ignore
    @Test
    public void testGet_KeyKeys() {
        System.out.println("get");
        KeyKeys keyValue = null;
        OneKey instance = new OneKey();
        CBORObject expResult = null;
        CBORObject result = instance.get(keyValue);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of get method, of class OneKey.
     */
    @Ignore
    @Test
    public void testGet_CBORObject() throws Exception {
        System.out.println("get");
        CBORObject keyValue = null;
        OneKey instance = new OneKey();
        CBORObject expResult = null;
        CBORObject result = instance.get(keyValue);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of generateKey method, of class OneKey.
     */
    @Ignore
    @Test
    public void testGenerateKey() throws Exception {
        System.out.println("generateKey");
        AlgorithmID algorithm = null;
        OneKey expResult = null;
        OneKey result = OneKey.generateKey(algorithm);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of PublicKey method, of class OneKey.
     */
    @Ignore
    @Test
    public void testPublicKey() {
        System.out.println("PublicKey");
        OneKey instance = new OneKey();
        OneKey expResult = null;
        OneKey result = instance.PublicKey();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of EncodeToBytes method, of class OneKey.
     */
    @Ignore
    @Test
    public void testEncodeToBytes() {
        System.out.println("EncodeToBytes");
        OneKey instance = new OneKey();
        byte[] expResult = null;
        byte[] result = instance.EncodeToBytes();
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of AsCBOR method, of class OneKey.
     */
    @Ignore
    @Test
    public void testAsCBOR() {
        System.out.println("AsCBOR");
        OneKey instance = new OneKey();
        CBORObject expResult = null;
        CBORObject result = instance.AsCBOR();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of AsPublicKey method, of class OneKey.
     */
    @Test
    public void testAsPublicKey() throws Exception {
        OneKey instance = OneKey.generateKey(AlgorithmID.ECDSA_256);
        PublicKey result = instance.AsPublicKey();
        assertEquals(result.getAlgorithm(), "EC");
        assertEquals(result.getFormat(), "X.509");
        
        byte[] rgbSPKI = result.getEncoded();
        String f =  byteArrayToHex(rgbSPKI);
        assertEquals(rgbSPKI.length, 91);
        
        KeyFactory kFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(rgbSPKI);
        PublicKey pubKey = (PublicKey) kFactory.generatePublic(spec);
    }

    /**
     * Test of AsPrivateKey method, of class OneKey.
     */
    @Test
    public void testAsPrivateKey() throws Exception {
        OneKey instance = OneKey.generateKey(AlgorithmID.ECDSA_256);
        PrivateKey result = instance.AsPrivateKey();
        
        assertEquals(result.getAlgorithm(), "EC");
        assertEquals(result.getFormat(), "PKCS#8");
        
        byte[] rgbPrivate = result.getEncoded();
        String x = byteArrayToHex(rgbPrivate);
        
        /*
        
        THis seems to go boom on jdk 9
        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("EC");
        
        */

        KeyFactory kFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
                
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rgbPrivate);
        PrivateKey pubKey = (PrivateKey) kFactory.generatePrivate(spec);
    }

    @Test
    public void testHasAlgorithmID_null() {
        OneKey key = new OneKey();
        Assert.assertTrue(key.HasAlgorithmID(null));
        Assert.assertFalse(key.HasAlgorithmID(AlgorithmID.ECDSA_384));
    }

    @Test
    public void testHasAlgorithmID_value() throws CoseException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        Assert.assertTrue(key.HasAlgorithmID(AlgorithmID.ECDSA_256));
        Assert.assertFalse(key.HasAlgorithmID(AlgorithmID.ECDSA_384));
    }

    @Test
    public void testHasKeyID_null() {
        OneKey key = new OneKey();
        Assert.assertTrue(key.HasKeyID(null));
    }

    @Test
    public void testHasKeyID_value() {
        String idStr = "testId";
        OneKey key = new OneKey();
        CBORObject id = CBORObject.FromObject(idStr);
        key.add(KeyKeys.KeyId, id);
        Assert.assertTrue(key.HasKeyID(idStr));
    }

    @Test
    public void testHasKeyOp_null() {
        OneKey key = new OneKey();
        Assert.assertTrue(key.HasKeyOp(null));
    }

    @Test
    public void testHasKeyOp_value() {
        OneKey key = new OneKey();
        key.add(KeyKeys.Key_Ops, CBORObject.FromObject(2));
        Assert.assertTrue(key.HasKeyOp(2));
    }

    @Test
    public void testHasKeyType_null() {
        OneKey key = new OneKey();
        Assert.assertTrue(key.HasKeyType(null));
    }

    @Test
    public void testHasKeyType_value() throws CoseException {
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        Assert.assertTrue(key.HasKeyType(KeyKeys.KeyType_EC2));
    }
    
    @Test
    public void testFromPublic() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, CoseException {
            ECGenParameterSpec paramSpec = new ECGenParameterSpec("P-256");
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(paramSpec);
            
            KeyPair keyPair = gen.genKeyPair();
            
            OneKey pubKey = new OneKey(keyPair.getPublic(), null);
            OneKey privKey = new OneKey(null, keyPair.getPrivate());
            OneKey bothKey = new OneKey(keyPair.getPublic(), keyPair.getPrivate());
        
    }
    
    @Test
    public void testRoundTrip() throws CoseException {
        CBORObject cborKey = CBORObject.NewMap();
        cborKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        cborKey.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        cborKey.Add(KeyKeys.EC2_D.AsCBOR(), hexStringToByteArray("6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19"));
        cborKey.Add(KeyKeys.EC2_Y.AsCBOR(), hexStringToByteArray("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"));
        cborKey.Add(KeyKeys.EC2_X.AsCBOR(), hexStringToByteArray("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"));
        
        OneKey oneKey = new OneKey(cborKey);
        PublicKey pubKey = oneKey.AsPublicKey();
        PrivateKey privKey = oneKey.AsPrivateKey();
        
        OneKey oneKey2 = new OneKey(pubKey, privKey);
        Assert.assertEquals(oneKey2.get(KeyKeys.KeyType), oneKey.get(KeyKeys.KeyType));
        Assert.assertEquals(oneKey2.get(KeyKeys.EC2_Curve), oneKey2.get(KeyKeys.EC2_Curve));
        Assert.assertArrayEquals(oneKey2.get(KeyKeys.EC2_X).GetByteString(), oneKey.get(KeyKeys.EC2_X).GetByteString());
        if (oneKey2.get(KeyKeys.EC2_Y).getType() == CBORType.ByteString) {
            Assert.assertArrayEquals(oneKey2.get(KeyKeys.EC2_Y).GetByteString(), oneKey.get(KeyKeys.EC2_Y).GetByteString());            
        }
        else {
            Assert.assertTrue("Need to implement this", false);
        }
        Assert.assertArrayEquals(oneKey2.get(KeyKeys.EC2_D).GetByteString(), oneKey.get(KeyKeys.EC2_D).GetByteString());
    }
     
    static String byteArrayToHex(byte[] a) {
       StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }  
    
}
