package COSE;


import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

public class KeySetTest {
  
  /**
   * Test of stream method of class KeySet.
   * @throws CoseException 
   */
  @Test
  public void testStream() throws CoseException {
    KeySet ks = new KeySet();
    OneKey ecdsa_256 = OneKey.generateKey(AlgorithmID.ECDSA_256);
    ks.add(ecdsa_256);
    ks.add(OneKey.generateKey(AlgorithmID.ECDSA_512));

    List<OneKey> filteredKeys = ks.stream()
        .filter(k-> k.HasAlgorithmID(AlgorithmID.ECDSA_256))
        .collect(Collectors.toList());
    Assert.assertEquals(1, filteredKeys.size());
    Assert.assertEquals(ecdsa_256, filteredKeys.get(0));

    // Do something like the following
    filteredKeys = ks.stream()
        .filter(k -> AlgorithmID.ECDSA_256.AsCBOR().equals(k.get(KeyKeys.Algorithm)))
        .collect(Collectors.toList());
    Assert.assertEquals(1, filteredKeys.size());
    Assert.assertEquals(ecdsa_256, filteredKeys.get(0));
  }

}
