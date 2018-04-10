/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.util.ArrayList;
import java.util.Arrays;

/**
 *
 * @author Jim
 */
public class ASN1 {
    
    /**
     * This class is used internal to the ASN.1 decoding functions.
     * After decoding there will be one of these for each item in the
     * original in the encoded byte array
     */
    public static class TagValue {
        public int tag;
        public byte[] value;
        public ArrayList<TagValue> list;
        
        public TagValue(int tagIn, byte[] valueIn) {
            tag = tagIn;
            value = valueIn;
        }
        
        public TagValue(int tagIn, ArrayList<TagValue> listIn) {
            tag = tagIn;
            list = listIn;
        }
    }
    
    // 1.2.840.10045.3.1.7
    public static final byte[] Oid_secp256r1 = new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};
    // 1.3.132.0.34
    public static final byte[] Oid_secp384r1 = new byte[]{0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x22};
    // 1.3.132.0.35
    public static final byte[] Oid_secp521r1 = new byte[]{0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x23};
    // 1.2.840.10045.2.1
    public static final byte[] oid_ecPublicKey = new byte[]{0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x2, 0x1};
    
    // 1.3.101.110
    public static final byte[] Oid_X25519 = new byte[]{0x6, 3, 0x2b, 101, 110};
    // 1.3.101.111
    public static final byte[] Oid_X448 = new byte[]{0x6, 3, 0x2b, 101, 111};
    // 1.3.101.112
    public static final byte[] Oid_Ed25519 = new byte[]{0x6, 0x3, 0x2b, 101, 112};
    //  1.3.101.113
    public static final byte[] Oid_Ed448 = new byte[]{0x6, 0x3, 0x2b, 101, 113};
    
    private static final byte[] SequenceTag = new byte[]{0x30};
    private static final byte[] OctetStringTag = new byte[]{0x4};
    private static final byte[] BitStringTag = new byte[]{0x3};
    
    /**
     * Encode a subject public key info structure from an OID and the data bytes
     * for the key
     * This function assumes that we are encoding an EC Public key.d
     * 
     * @param oid - encoded Object Identifier
     * @param keyBytes - encoded key bytes
     * @return - encoded SPKI
     */
    public static byte[] EncodeSubjectPublicKeyInfo(byte[] algorithm, byte[] keyBytes) throws CoseException
    {
        //  SPKI ::= SEQUENCE {
        //       algorithm   SEQUENCE {
        //            oid = id-ecPublicKey {1 2 840 10045 2}
        //            namedCurve = oid for algorithm
        //       }
        //       subjectPublicKey BIT STRING CONTAINS  key bytes
        //  }
        try {        
            ArrayList<byte[]> xxx = new ArrayList<byte[]>();
            xxx.add(algorithm);
            xxx.add(new byte[]{3});
            xxx.add(ComputeLength(keyBytes.length+1));
            xxx.add(new byte[]{0});
            xxx.add(keyBytes);

            return Sequence(xxx);
        }
        catch (ArrayIndexOutOfBoundsException e) {
            System.out.print(e.toString());
            throw e;
        }
    }
    
    /**
     * Encode an EC Private key
     * @param oid - curve to use
     * @param keyBytes - bytes of the key
     * @param spki - optional SPKI
     * @return
     * @throws CoseException
     */
    public static byte[] EncodeEcPrivateKey(byte[] oid, byte[] keyBytes, byte[] spki) throws CoseException
    {
        //  ECPrivateKey ::= SEQUENCE {
        //     version  INTEGER {1}
        //     privateKey OCTET STRING
        //     parameters [0] OBJECT IDENTIFIER = named curve
        //     public key [1] BIT STRING OPTIONAL
        //  }
        //

        ArrayList<byte[]> xxx = new ArrayList<byte[]>();
        xxx.add(new byte[]{2, 1, 1});
        xxx.add(OctetStringTag);
        xxx.add(ComputeLength(keyBytes.length));
        xxx.add(keyBytes);
        xxx.add(new byte[]{(byte)0xa0});
        xxx.add(ComputeLength(oid.length));
        xxx.add(oid);
        if (spki != null) {
            xxx.add(new byte[]{(byte)0xa1});
            xxx.add(ComputeLength(spki.length+1));
            xxx.add(new byte[]{0});
            xxx.add(spki);
        }
        
        byte[] ecPrivateKey = Sequence(xxx);
     
        return ecPrivateKey;
    }

    /*
     *  Decode an object which is supposed to be a SubjectPublicKeyInfo strucuture
     * and check that the right set of fields are in the right place
     * 
     * @param encoding encoded byte string to decode
     * @return decoded structure
     * @throws CoseException
     */
    public static ArrayList<TagValue> DecodeSubjectPublicKeyInfo(byte[] encoding) throws CoseException
    {
        TagValue spki = DecodeCompound(0, encoding);
        if (spki.tag != 0x30) throw new CoseException("Invalid SPKI");
        ArrayList<TagValue> tvl = spki.list;
        if (tvl.size() != 2) throw new CoseException("Invalid SPKI");
        
        if (tvl.get(0).tag != 0x30) throw new CoseException("Invalid SPKI");
        if (tvl.get(0).list.isEmpty() || tvl.get(0).list.size() > 2) {
            throw new CoseException("Invalid SPKI");
        }
        if (tvl.get(0).list.get(0).tag != 6) throw new CoseException("Invalid SPKI");
        //  tvl.get(0).list.get(1).tag is an ANY so needs to be checked elsewhere
        if (tvl.get(1).tag != 3) throw new CoseException("Invalid SPKI");
        
        return tvl;
    }
    
    /**
     * Decode an array of bytes which is supposed to be an ASN.1 encoded structure.
     * This code does the decoding w/o any reference to a schema for what is being
     * decoded so it returns type and value pairs rather than converting the values
     * to the correct underlying data type.
     * 
     * One oddity that needs to be observed is that Object Identifiers do not have
     * the type and length removed from them.  This is because we do a byte wise comparison
     * and started doing the entire item rather than just the value portion.
     * 
     * M00BUG - we should check that we don't overflow during the decoding process.
     * 
     * @param offset - starting offset in array to begin decoding
     * @param encoding - bytes of the ASN.1 encoded value
     * @return Decoded structure
     * @throws CoseException
     */
    public static TagValue DecodeCompound(int offset, byte[] encoding) throws CoseException
    {
        ArrayList<TagValue> result = new ArrayList<TagValue>();
        int retTag = encoding[offset];
        
        //  We only decode objects which are compound objects.  That means that this bit must be set
        
        if ((encoding[offset] & 0x20) != 0x20) throw new CoseException("Invalid structure");
        int[] l = DecodeLength(offset+1, encoding);
        int sequenceLength = l[1];
        if (offset + sequenceLength > encoding.length) throw new CoseException("Invalid sequence");
        offset += l[0]+1;

        while (sequenceLength > 0) {
            int tag = encoding[offset];
            l = DecodeLength(offset+1, encoding);
            if (l[1] > sequenceLength) throw new CoseException("Invalid sequence");

            if ((tag & 0x20) != 0) {
                result.add(DecodeCompound(offset, encoding));
                offset += 1 + l[0] + l[1];
                sequenceLength -= 1 + l[0] + l[1];                    
            }
            else {
                // At some point we might want to fix this.
                if (tag == 6) {
                    result.add(new TagValue(tag, Arrays.copyOfRange(encoding, offset, offset+l[1]+l[0]+1)));                
                }
                else {
                    result.add(new TagValue(tag, Arrays.copyOfRange(encoding, offset+l[0]+1, offset+1+l[0]+l[1])));
                }
                offset += 1 + l[0] + l[1];
                sequenceLength -= 1 + l[0] + l[1];
            }
        }
        
        return new TagValue(retTag, result);
    }
    
    /**
     * Encode a private key into a PKCS#8 private key structure.
     * 
     * @param oid - EC curve OID
     * @param keyBytes - raw bytes of the key
     * @param spki - optional subject public key info structure to include
     * @return byte array of encoded bytes
     * @throws CoseException
     */
    public static byte[] EncodePKCS8(byte[] algorithm, byte[] keyBytes, byte[] spki) throws CoseException
    {
        //  PKCS#8 ::= SEQUENCE {
        //     version INTEGER {0}
        //      privateKeyALgorithm SEQUENCE {
        //           algorithm OID,
        //           parameters ANY
        //      }
        //     privateKey ECPrivateKey,
        //     attributes [0] IMPLICIT Attributes OPTIONAL
        //     publicKey [1] IMPLICIT BIT STRING OPTIONAL
        //   }
        
        try {

          ArrayList<byte[]> xxx = new ArrayList<byte[]>();
            xxx.add(new byte[]{2, 1, 0});
            xxx.add(algorithm);
            xxx.add(OctetStringTag);
            xxx.add(ComputeLength(keyBytes.length));
            xxx.add(keyBytes);

            return Sequence(xxx);
        }
        catch (ArrayIndexOutOfBoundsException e) {
            System.out.print(e.toString());
            throw e;
        }
    }
    
    /**
     * Decode an EC PKCS#8 private key structure
     * 
     * @param encodedData bytes containing the private key
     * @return tag/value from the decoded object
     * @throws CoseException
     */
    public static ArrayList<TagValue> DecodePKCS8(byte[] encodedData) throws CoseException 
    {
        TagValue pkcs8 = DecodeCompound(0, encodedData);
        if (pkcs8.tag != 0x30) throw new CoseException("Invalid PKCS8 structure");
        ArrayList<TagValue> retValue = pkcs8.list;
        if (retValue.size() != 3 && retValue.size() != 4) {
            throw new CoseException("Invalid PKCS8 structure");
        }

        // Version number - we currently only support one version
        if (retValue.get(0).tag != 2 && ((byte[]) retValue.get(0).value)[0] != 0) {
            throw new CoseException("Invalid PKCS8 structure");
        }

        // Algorithm identifier
        if (retValue.get(1).tag != 0x30) throw new CoseException("Invalid PKCS8 structure");
        if (retValue.get(1).list.isEmpty() || retValue.get(1).list.size() > 2) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        if (retValue.get(1).list.get(0).tag != 6) throw new CoseException("Invalid PKCS8 structure");
        //  Dont check the next item as it is an ANY
        
        if (retValue.get(2).tag != 4) throw new CoseException("Invalid PKCS8 structure");
        
        // This is attributes, but we are not going to check for correctness.
        if (retValue.size() == 4 && retValue.get(3).tag != 0xa0) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        
        //  Decode the contents of the octet string PrivateKey
        
        byte[] pk = (byte[]) retValue.get(2).value;
        TagValue pkd = DecodeCompound(0, pk);
        ArrayList<TagValue> pkdl = pkd.list;
        if (pkd.tag != 0x30) throw new CoseException("Invalid ECPrivateKey");
        if (pkdl.size() < 2 || pkdl.size() > 4) throw new CoseException("Invalid ECPrivateKey");
        
        if (pkdl.get(0).tag != 2 && ((byte[]) retValue.get(0).value)[0] != 1) {
            throw new CoseException("Invalid ECPrivateKey");
        }
        
        if (pkdl.get(1).tag != 4) throw new CoseException("Invalid ECPrivateKey");
        
        if (pkdl.size() > 2) {
            if ((pkdl.get(2).tag & 0xff) != 0xA0) {
                if (pkdl.size() != 3 || (pkdl.get(2).tag & 0xff) != 0xa1) {
                    throw new CoseException("Invalid ECPrivateKey");
                }
            } else {
                if (pkdl.size() == 4 && (pkdl.get(3).tag & 0xff) != 0xa1) throw new CoseException("Invalid ECPrivateKey");                
            }
        }
        
        retValue.get(2).list = pkdl;
        retValue.get(2).value = null;
        retValue.get(2).tag = 0x30;
        
        return retValue;
    }
    
    public static byte[] EncodeSignature(byte[] r, byte[] s) throws CoseException {
        ArrayList<byte[]> x = new ArrayList<byte[]>();
        x.add(UnsignedInteger(r));
        x.add(UnsignedInteger(s));

        return Sequence(x);
    }
    
    public static byte[] EncodeOctetString(byte[] data) throws CoseException {
        ArrayList<byte[]> x = new ArrayList<byte[]>();
        x.add(OctetStringTag);
        x.add(ComputeLength(data.length));
        x.add(data);
        
        return ToBytes(x);
    }
    
    public static byte[] AlgorithmIdentifier(byte[] oid, byte[] params) throws CoseException
    {
        ArrayList<byte[]> xxx = new ArrayList<byte[]>();
        xxx.add(oid);
        if (params != null) {
            xxx.add(params);
        }
        return Sequence(xxx);
    }
    
    private static byte[] Sequence(ArrayList<byte[]> members) throws CoseException
    {
        byte[] y = ToBytes(members);
        ArrayList<byte[]> x = new ArrayList<byte[]>();
        x.add(SequenceTag);
        x.add(ComputeLength(y.length));
        x.add(y);
        
        return ToBytes(x);
    }
    
    private static byte[] UnsignedInteger(byte[] i) throws CoseException {
        int pad = 0, offset = 0;

        while (offset < i.length && i[offset] == 0) {
            offset++;
        }

        if (offset == i.length) {
            return new byte[] {0x02, 0x01, 0x00};
        }
        if ((i[offset] & 0x80) != 0) {
            pad++;
        }
        
        // M00BUG if the integer is > 127 bytes long with padding
        
        int length = i.length - offset;
        byte[] der = new byte[2 + length + pad];
        der[0] = 0x02;
        der[1] = (byte)(length + pad);
        System.arraycopy(i, offset, der, 2 + pad, length);

        return der;
    }
    
    private static byte[] ComputeLength(int x) throws CoseException
    {
        if (x <= 127) {
            return new byte[]{(byte)x};
        }
        else if ( x < 256) {
            return new byte[]{(byte) 0x81, (byte) x};
        }
        throw new CoseException("Error in ASN1.GetLength");
    }
    
    private static int[] DecodeLength(int offset, byte[] data) throws CoseException
    {
        int length;
        int i;
        
        if ((data[offset] & 0x80) == 0) return new int[]{1, data[offset]};
        if (data[offset] == 0x80) {
            throw new CoseException("Indefinite length encoding not supported");
        }
        length = data[offset] & 0x7f;
        int retValue = 0;
        for (i=0; i<length; i++) {
            retValue = retValue*256 + (data[i+offset+1] & 0xff);
        }
        
        return new int[]{length+1, retValue};
    }
    
    private static byte[] ToBytes(ArrayList<byte[]> x)
    {
        int l = 0;
        l = x.stream().map((r) -> r.length).reduce(l, Integer::sum);
        
        byte[] b = new byte[l];
        l = 0;
        for (byte[] r : x) {
            System.arraycopy(r, 0, b, l, r.length);
            l += r.length;
        }
        
        return b;
    }    
}
