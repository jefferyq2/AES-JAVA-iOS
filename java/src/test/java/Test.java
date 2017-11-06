import org.apache.commons.codec.binary.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class Test {
  private static BouncyCipher cipher = null;

  public static void main(String... arg) throws Exception {
    try {
      BouncyCipher cipher = new BouncyCipher();
      String test = "1234";
      byte[] encrypt = cipher.encrypt(test.getBytes("UTF-8"));
      String s1 = new String(Base64.encodeBase64(encrypt));
      String s2 = cipher.encrypt(test);
      System.out.println(String.format("%s - %s - %b", s1, s2, s1.equals(s2)));

      byte[] bytes1 = Base64.decodeBase64(s1);
      byte[] decrypt = cipher.decrypt(bytes1);
      String t1 = new String(decrypt);

      String t2 = cipher.decrypt(s1);
      System.out.println(String.format("%s - %s - %b", t1, t2, t1.equals(t2)));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  @org.junit.Before
  public void setUp() throws Exception {
    cipher = new BouncyCipher();
  }

  @org.junit.Test
  public void encryptText() throws Exception {
    assertTrue(true);
    String test = "1234";
    byte[] encrypt = cipher.encrypt(test.getBytes("UTF-8"));
    String s1 = new String(Base64.encodeBase64(encrypt));
    String s2 = cipher.encrypt(test);
    System.out.println(s1 + " " + s2);
    assertEquals(s1, s2);
  }

  @org.junit.Test
  public void decryptText() throws Exception {
    String enc = "7h68uznZ42KXri+Gx8E+aA==";

    byte[] bytes1 = Base64.decodeBase64(enc);
    byte[] decrypt = cipher.decrypt(bytes1);
    String t1 = new String(decrypt);
    assertEquals("1234", t1);
    String t2 = cipher.decrypt(enc);
    assertEquals("1234", t2);

  }
}
