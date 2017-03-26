/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package COSE;

import com.upokecenter.cbor.CBORObject;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 *
 * @author jimsch
 */
/*
 * Ways to search
 *  - Given KeySet and key id, return a KeySet (more than one key may have the same
 * key id)
 *  - Filter on the algo used, key usage bits (only keys that can be used for signing, or
 * specific types)
 *  - Look at other fields from specs that can be used to do fast filters, vs
 * iteration.
 *  - By curve. Need to look at key type and curve
 */
public class KeySet {
  private List<OneKey> keys;

  public KeySet() {
    keys = new ArrayList<OneKey>();
  }

  public KeySet(CBORObject keysIn) {
    keys = new ArrayList<OneKey>();

    // Ignore keys which we cannot deal with or are malformed.

    for (int i = 0; i < keysIn.size(); i++) {
      try {
        keys.add(new OneKey(keysIn.get(i)));
      } catch (CoseException e) {
        ;
      }
    }
  }

  public void add(OneKey key) {
    keys.add(key);
  }

  public List<OneKey> getList() {
    return keys;
  }

  public void remove(OneKey key) {
    keys.remove(key);
  }

  public Stream<OneKey> stream() {
    return keys.stream();
  }

  public Stream<OneKey> parallelStream() {
    return keys.parallelStream();
  }
}
