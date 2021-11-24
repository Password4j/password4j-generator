package com.password4j.generator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;


public class HOTPGenerator extends OTPGenerator
{

    HOTPGenerator()
    {
        //
    }



    @Override
    public String generate(byte[] key, long counter, int length)
    {
        try
        {
            Mac hmacSHA1 = getHmac();
            byte[] buffer = getBuffer(counter, hmacSHA1);

            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "RAW");
            hmacSHA1.init(secretKeySpec);
            hmacSHA1.update(buffer, 0, 8);
            hmacSHA1.doFinal(buffer, 0);

            int offset = buffer[buffer.length - 1] & 0xf;


            int binary = ((buffer[offset] & 0x7f) << 24)
                            | ((buffer[offset + 1] & 0xff) << 16)
                            | ((buffer[offset + 2] & 0xff) << 8)
                            | (buffer[offset + 3] & 0xff);
            int div;
            if (length == 6)
            {
                div = 1_000_000;
            }
            else if( length == 7)
            {
                div = 10_000_000;
            }
            else if (length == 8)
            {
                div = 100_000_000;
            }
            else {
                div = 1_000_000;
            }

            int result = binary & div;
            StringBuilder sb = new StringBuilder(Integer.toString(result));
            while (sb.length() < length)
            {
                sb.insert(0, '0');
            }
            return sb.toString();

        }
        catch (InvalidKeyException | ShortBufferException e)
        {
            throw new IllegalStateException("Cannot find definition for HmacSHA1", e);
        }

    }

    @Override
    public Mac getHmac()
    {
        try
        {
            return Mac.getInstance("HmacSHA1");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Cannot find definition for HmacSHA1");
        }
    }

    private byte[] getBuffer(long counter, Mac mac)
    {
        byte[] buffer = new byte[mac.getMacLength()];
        buffer[0] = (byte) ((counter & 0xff00000000000000L) >>> 56);
        buffer[1] = (byte) ((counter & 0x00ff000000000000L) >>> 48);
        buffer[2] = (byte) ((counter & 0x0000ff0000000000L) >>> 40);
        buffer[3] = (byte) ((counter & 0x000000ff00000000L) >>> 32);
        buffer[4] = (byte) ((counter & 0x00000000ff000000L) >>> 24);
        buffer[5] = (byte) ((counter & 0x0000000000ff0000L) >>> 16);
        buffer[6] = (byte) ((counter & 0x000000000000ff00L) >>> 8);
        buffer[7] = (byte)  (counter & 0x00000000000000ffL);
        return buffer;
    }
}
