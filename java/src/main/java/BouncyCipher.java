import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class BouncyCipher {
  final static byte[] SECURE_KEY_IN_BYTES_OMG = new byte[] {
    //@formatter:off
    0x65, 0x69, 0x67, 0x68,
    0x74, 0x65, 0x65, 0x6e,
    0x2e, 0x6c, 0x65, 0x74,
    0x74, 0x65, 0x72, 0x73,
    0x2e
    //@formatter:on
  };
  public static final String UTF_8 = "UTF-8";
  private final String password;

  public BouncyCipher() throws Exception {
    String s = Hex.encodeHexString(SECURE_KEY_IN_BYTES_OMG);
    byte[] key_in_bytes_hex = Hex.decodeHex(s.toCharArray());
    this.password = new String(key_in_bytes_hex);
  }

  public byte[] encrypt(byte[] plainText) throws Exception {
    return transform(true, plainText);
  }

  public String encrypt(String plainText) throws Exception {
    byte[] transform = transform(true, plainText.getBytes(UTF_8));
    return new String(Base64.encodeBase64(transform));
  }

  public byte[] decrypt(byte[] cipherText) throws Exception {
    return transform(false, cipherText);
  }

  public String decrypt(String cipherText) throws Exception {
    byte[] bytes = Base64.decodeBase64(cipherText);
    return new String(transform(false, bytes));
  }

  private byte[] transform(boolean encrypt, byte[] inputBytes) throws Exception {
    byte[] key = DigestUtils.md5(password.getBytes(UTF_8));
    BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
    cipher.init(encrypt, new KeyParameter(key));
    ByteArrayInputStream input = new ByteArrayInputStream(inputBytes);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    int inputLen;
    int outputLen;
    byte[] inputBuffer = new byte[1024];
    byte[] outputBuffer = new byte[cipher.getOutputSize(inputBuffer.length)];
    while ((inputLen = input.read(inputBuffer)) > -1) {
      outputLen = cipher.processBytes(inputBuffer, 0, inputLen, outputBuffer, 0);
      if (outputLen > 0) {
        output.write(outputBuffer, 0, outputLen);
      }
    }
    outputLen = cipher.doFinal(outputBuffer, 0);
    if (outputLen > 0) {
      output.write(outputBuffer, 0, outputLen);
    }
    return output.toByteArray();
  }

}
