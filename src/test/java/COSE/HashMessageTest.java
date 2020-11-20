/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import com.upokecenter.cbor.CBORObject;
import org.junit.*;
import static org.junit.Assert.*;
import org.junit.rules.ExpectedException;

public class HashMessageTest extends TestBase {
	byte[] rgbContent = { 'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'o', 'm', 'e', ' ', 'c', 'o', 'n', 't', 'e', 'n',
			't' };

	public HashMessageTest() {
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
	 * Test of hash method, of class HashMessage.
	 */
	@Test
	public void testRoundTrip() throws Exception {
		System.out.println("Round Trip");
		HashMessage msg = new HashMessage();
		msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.SHA3_256.AsCBOR(), Attribute.PROTECTED);
		msg.SetContent(rgbContent);
		msg.hash();
		byte[] rgbMsg = msg.EncodeToBytes();

		msg = (HashMessage) Message.DecodeFromBytes(rgbMsg, MessageTag.Hash);

		assertNotEquals(rgbContent, msg.getHashedContent());
	}

	@Test
	public void hashNoAlgorithm() throws CoseException {
		HashMessage msg = new HashMessage();

		thrown.expect(CoseException.class);
		thrown.expectMessage("No Algorithm Specified");
		msg.SetContent(rgbContent);
		msg.hash();
	}

	@Test
	public void hashUnknownAlgorithm() throws CoseException {
		HashMessage msg = new HashMessage();

		thrown.expect(CoseException.class);
		thrown.expectMessage("Unknown Algorithm Specified");
		msg.addAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attribute.PROTECTED);
		msg.SetContent(rgbContent);
		msg.hash();
	}

	@Test
	public void encryptUnsupportedAlgorithm() throws CoseException {
		HashMessage msg = new HashMessage();

		thrown.expect(CoseException.class);
		thrown.expectMessage("Unsupported Algorithm Specified");
		msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.HMAC_SHA_256.AsCBOR(), Attribute.PROTECTED);
		msg.SetContent(rgbContent);
		msg.hash();
	}

	@Test
	public void hashNoContent() throws CoseException {
		HashMessage msg = new HashMessage();

		thrown.expect(CoseException.class);
		thrown.expectMessage("No Content Specified");
		msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.SHA3_256.AsCBOR(), Attribute.PROTECTED);
		msg.hash();
	}

	@Test
	public void hashNoTag() throws CoseException {
		HashMessage msg = new HashMessage(false, true);

		msg.addAttribute(HeaderKeys.Algorithm, AlgorithmID.SHA3_256.AsCBOR(), Attribute.PROTECTED);
		msg.SetContent(rgbContent);
		msg.hash();
		CBORObject cn = msg.EncodeCBORObject();

		assert (!cn.isTagged());
	}

	@Test
	public void hashWrongBasis() throws CoseException {
		CBORObject obj = CBORObject.NewMap();

		thrown.expect(CoseException.class);
		thrown.expectMessage("Message is not a COSE security Message");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}

	@Test
	public void hashDecodeWrongCount() throws CoseException {
		CBORObject obj = CBORObject.NewArray();
		obj.Add(CBORObject.False);

		thrown.expect(CoseException.class);
		thrown.expectMessage("Invalid Hash structure");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}

	@Test
	public void hashDecodeBadProtected() throws CoseException {
		CBORObject obj = CBORObject.NewArray();
		obj.Add(CBORObject.False);
		obj.Add(CBORObject.False);
		obj.Add(CBORObject.False);

		thrown.expect(CoseException.class);
		thrown.expectMessage("Invalid Hash structure");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}

	@Test
	public void hashDecodeBadProtected2() throws CoseException {
		CBORObject obj = CBORObject.NewArray();
		obj.Add(CBORObject.FromObject(CBORObject.False));
		obj.Add(CBORObject.False);
		obj.Add(CBORObject.False);

		thrown.expect(CoseException.class);
		thrown.expectMessage("Invalid Hash structure");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}

	@Test
	public void hashDecodeBadUnprotected() throws CoseException {
		CBORObject obj = CBORObject.NewArray();
		obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
		obj.Add(CBORObject.False);
		obj.Add(CBORObject.False);

		thrown.expect(CoseException.class);
		thrown.expectMessage("Invalid Hash structure");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}

	@Test
	public void hashDecodeBadContent() throws CoseException {
		CBORObject obj = CBORObject.NewArray();
		obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
		obj.Add(CBORObject.NewMap());
		obj.Add(CBORObject.False);

		thrown.expect(CoseException.class);
		thrown.expectMessage("Invalid Hash structure");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}

	@Test
	public void hashDecodeBadTag() throws CoseException {
		CBORObject obj = CBORObject.NewArray();
		obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
		obj.Add(CBORObject.NewMap());
		obj.Add(new byte[0]);

		thrown.expect(CoseException.class);
		thrown.expectMessage("Invalid Hash structure");

		byte[] rgb = obj.EncodeToBytes();
		Message msg = Message.DecodeFromBytes(rgb, MessageTag.Hash);
	}
}
