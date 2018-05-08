/*
 * Test vector generator for SCP03 KDF
 *
 * Source code:
 * Derived from GlobalPlatformPro by Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class test {
    private static byte[] scp03_kdf(byte[] key, byte constant, byte[] context, int blocklen_bits) {
        // 11 bytes
        byte[] label = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try {
            bo.write(label); // 11 bytes of label
            bo.write(constant); // constant for the last byte
            bo.write(0x00); // separator
            bo.write((blocklen_bits >> 8) & 0xFF); // block size in two bytes
            bo.write(blocklen_bits & 0xFF);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
        byte[] blocka = bo.toByteArray();
        byte[] blockb = context;
        return scp03_kdf(key, blocka, blockb, blocklen_bits/8);
    }

    // Generic KDF in counter mode with one byte counter.
    public static byte[] scp03_kdf(byte[] key, byte[] a, byte[] b, int bytes) {
        BlockCipher cipher = new AESEngine();
        CMac cmac = new CMac(cipher);
        KDFCounterBytesGenerator kdf = new KDFCounterBytesGenerator(cmac);
        kdf.init(new KDFCounterParameters(key, a, b, 8)); // counter size is in bits
        byte[] cgram = new byte[bytes];
        kdf.generateBytes(cgram, 0, cgram.length);
        return cgram;
    }
public static void main(String argv[]) {
   byte[] KI = new byte[16];
   byte[] KO;
   byte[] context = new byte[16];
   byte constant = 0;
   for (int i = 0; i < 40; i++) {
      int bytes = ((i%5) > 2) ? 16:32;
      constant++;
      KO = scp03_kdf(KI, constant, context, bytes*8);
      System.out.printf("%s %x %s %s\n",
         javax.xml.bind.DatatypeConverter.printHexBinary(KI),
         constant, 
         javax.xml.bind.DatatypeConverter.printHexBinary(context),
         javax.xml.bind.DatatypeConverter.printHexBinary(KO));
      KI = context;
      context = KO;
  }
}
}
