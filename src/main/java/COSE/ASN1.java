/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.util.ArrayList;

/**
 *
 * @author Jim
 */
public class ASN1 {
    // 1.2.840.10045.3.1.7
    public static final byte[] Oid_secp256r1 = new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07};
    // 1.3.132.0.34
    public static final byte[] Oid_secp384r1 = new byte[]{0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x22};
    // 1.3.132.0.35
    public static final byte[] Oid_secp521r1 = new byte[]{0x06, 0x05, 0x2B, (byte) 0x81, 0x04, 0x00, 0x23};

    static final byte[] oid_ecPublicKey = new byte[]{0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x2, 0x1};
    
    
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
