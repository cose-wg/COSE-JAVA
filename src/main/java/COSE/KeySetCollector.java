/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.util.Collections;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

public class KeySetCollector implements Collector<OneKey, KeySet, KeySet> {

  @Override
  public Supplier<KeySet> supplier() {
    return KeySet::new;
 }

  @Override
  public BiConsumer<KeySet, OneKey> accumulator() {
    return (acc, elem) -> acc.add(elem);
  }

  @Override
  public BinaryOperator<KeySet> combiner() {
    // parallel streams are not supported
    return (acc1, acc2) -> {
      throw new UnsupportedOperationException("parallel streams are not supported");
    };
  }

  @Override
  public Function<KeySet, KeySet> finisher() {
    return (acc) -> acc;
  }

  @Override
  public Set<Collector.Characteristics> characteristics() {
    return Collections.emptySet();
  }
}
