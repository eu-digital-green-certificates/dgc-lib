package eu.europa.ec.dgc;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

public class DgcLibAutoConfigurationTest {

  @Test
  public void testDefineConstructor() {
    assertNotNull(new DgcLibAutoConfiguration());
  }
}
