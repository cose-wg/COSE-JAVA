/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package COSE;

import com.upokecenter.cbor.CBORObject;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author jimsch
 */
public class OneKeyTest {

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
   * Test of GetCurve method, of class OneKey.
   */
  @Ignore
  @Test
  public void testGetCurve() throws Exception {
    System.out.println("GetCurve");
    OneKey instance = new OneKey();
    X9ECParameters expResult = null;
    X9ECParameters result = instance.GetCurve();
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
    String f = byteArrayToHex(rgbSPKI);
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

    KeyPairGenerator kpgen = KeyPairGenerator.getInstance("EC");

    KeyFactory kFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());

    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(rgbPrivate);
    PrivateKey pubKey = (PrivateKey) kFactory.generatePrivate(spec);
  }

  static String byteArrayToHex(byte[] a) {
    StringBuilder sb = new StringBuilder(a.length * 2);
    for (byte b : a)
      sb.append(String.format("%02x", b & 0xff));
    return sb.toString();
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
}
