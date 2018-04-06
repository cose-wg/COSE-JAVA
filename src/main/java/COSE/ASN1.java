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

    public static final byte[] oid_ecPublicKey = new byte[]{0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x2, 0x1};
    
    
    private static final byte[] SequenceX = new byte[]{0x30};
    
    /**
     * Encode a subject public key info structure from an oid and the data bytes
     * for the key
     * 
     * @param oid - encoded Object Identifier
     * @param keyBytes - encoded key bytes
     * @return - encoded SPKI
     */
    public static byte[] EncodeSubjectPublicKeyInfo(byte[] oid, byte[] keyBytes) throws CoseException
    {
        //  SPKI ::= SEQUENCE {
        //       algorithm   SEQUENCE {
        //            oid = id-ecPublicKey {1 2 840 10045 2}
        //            namedCurve = oid for algorithm
        //       }
        //       subjectPublicKey BIT STRING CONTAINS  key bytes
        //       }
        //  }
        try {
        
        ArrayList<byte[]> xxx = new ArrayList<byte[]>();
        xxx.add(AlgorithmIdentifier(oid_ecPublicKey, oid));
        xxx.add(new byte[]{3});
        xxx.add(GetLength(keyBytes.length+1));
        xxx.add(new byte[]{0});
        xxx.add(keyBytes);
       
        return Sequence(xxx);
        }
        catch (ArrayIndexOutOfBoundsException e) {
            System.out.print(e.toString());
            throw e;
        }
    }
    
    public static ArrayList<TagValue> DecodeSubjectPublicKeyInfo(byte[] encoding) throws CoseException
    {
        TagValue spki = DecodeCompound(0, encoding);
        if (spki.tag != 0x30) throw new CoseException("Invalid SPKI");
        ArrayList<TagValue> tvl = spki.list;
        
        if (tvl.get(0).tag != 0x30) throw new CoseException("Invalid SPKI");
        if (tvl.get(1).tag != 3) throw new CoseException("Invalid SPKI");
        
        return tvl;
    }
    
    public static TagValue DecodeCompound(int offset, byte[] encoding) throws CoseException
    {
        ArrayList<TagValue> result = new ArrayList<TagValue>();
        if ((encoding[offset] & 0x20) != 0x20) throw new CoseException("Invalid structure");
        int[] l = DecodeLength(offset+1, encoding);
        int sequenceLength = l[1];
        if (offset + sequenceLength > encoding.length) throw new CoseException("Invalid sequence");
        offset += l[0]+1;

        while (sequenceLength > 0) {
            int tag = encoding[offset];
            if ((tag & 0x20) != 0) {
                // Cheat and assume we only do sequences.  Otherwise generalize this function
                l = DecodeLength(offset+1, encoding);
                result.add(DecodeCompound(offset, encoding));
                offset += 1 + l[0] + l[1];
                sequenceLength -= 1 + l[0] + l[1];                    
            }
            else {
                l = DecodeLength(offset+1, encoding);
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
        
        return new TagValue(encoding[0], result);
    }
    
    public static byte[] EncodePKCS8(byte[] oid, byte[] keyBytes, byte[] spki) throws CoseException
    {
        //  ECPrivateKey ::= SEQUENCE {
        //     version  INTEGER {1}
        //     privateKey OCTET STRING
        //     parameters [0] OBJECT IDENTIFIER = named curve
        //     public key [1] BIT STRING OPTIONAL
        //  }
        //
        //  PKCS#8 ::= SEQUENCE {
        //     version INTEGER {0}
        //      privateKeyALgorithm SEQUENCE {
        //           algorithm OID,
        //           parameters ANY
        //      }
        //     privateKey ECPrivateKey,
        //     attributes [0] IMPLICIT Attributes OPTIONAL
        //   }
        
        try {
        ArrayList<byte[]> xxx = new ArrayList<byte[]>();
        xxx.add(new byte[]{2, 1, 1});
        xxx.add(new byte[]{4});
        xxx.add(GetLength(keyBytes.length));
        xxx.add(keyBytes);
        xxx.add(new byte[]{(byte)0xa0});
        xxx.add(GetLength(oid.length));
        xxx.add(oid);
        if (spki != null) {
            xxx.add(new byte[]{(byte)0xa1});
            xxx.add(GetLength(spki.length));
            xxx.add(spki);
        }
        
        byte[] ecPrivateKey = Sequence(xxx);
        
        xxx = new ArrayList<byte[]>();
        xxx.add(new byte[]{2, 1, 0});
        xxx.add(AlgorithmIdentifier(oid_ecPublicKey, oid));
        xxx.add(new byte[]{4});
        xxx.add(GetLength(ecPrivateKey.length));
        xxx.add(ecPrivateKey);
        
        return Sequence(xxx);
        }
        catch (ArrayIndexOutOfBoundsException e) {
            System.out.print(e.toString());
            throw e;
        }
    }
    
    public static ArrayList<TagValue> DecodePKCS8(byte[] encodedData) throws CoseException 
    {
        TagValue pkcs8 = DecodeCompound(0, encodedData);
        if (pkcs8.tag != 0x30) throw new CoseException("Invalid PKCS8 structure");
        ArrayList<TagValue> retValue = pkcs8.list;
        if (retValue.get(0).tag != 2 && ((byte[]) retValue.get(0).value)[0] != 0) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        if (retValue.get(1).tag != 0x30) throw new CoseException("Invalid PKCS8 structure");
        if (retValue.get(2).tag != 4) throw new CoseException("Invalid PKCS8 structure");
        byte[] pk = (byte[]) retValue.get(2).value;
        TagValue pkd = DecodeCompound(0, pk);
        ArrayList<TagValue> pkdl = pkd.list;
        if (pkdl.get(0).tag != 2 && ((byte[]) retValue.get(0).value)[0] != 1) {
            throw new CoseException("Invalid Private Key structure");
        }
        if (pkdl.get(1).tag != 4) throw new CoseException("Invalid Private Key structure");
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
    
    private static byte[] AlgorithmIdentifier(byte[] oid, byte[] params) throws CoseException
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
        x.add(SequenceX);
        x.add(GetLength(y.length));
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
        int length = i.length - offset;
        byte[] der = new byte[2 + length + pad];
        der[0] = 0x02;
        der[1] = (byte)(length + pad);
        System.arraycopy(i, offset, der, 2 + pad, length);

        return der;
    }
    
    private static byte[] GetLength(int x) throws CoseException
    {
        if (x <= 127) {
            return new byte[]{(byte)x};
        }
        else if ( x < 256) {
            return new byte[]{(byte) 0x81, (byte) x};
        }
        throw new CoseException("Error in ASN1.GetLength");
    }
    
    private static int[] DecodeLength(int offset, byte[] data)
    {
        int length;
        int i;
        
        if ((data[offset] & 0x80) == 0) return new int[]{1, data[offset]};
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
        for (byte[] r : x) {
            l += r.length;
        }
        
        byte[] b = new byte[l];
        l = 0;
        for (byte[] r : x) {
            System.arraycopy(r, 0, b, l, r.length);
            l += r.length;
        }
        
        return b;
    }
    
    
}
