package eu.europa.ec.dgc;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class DgcLibAutoConfigurationTest {

  @Test
  public void testDefineConstructor() {
    assertNotEquals(new DgcLibAutoConfiguration(), null);
  }
}
