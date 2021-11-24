package com.password4j.generator;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.password4j.types.Hmac;


class OTPGenerator
{

    public static String generate(byte[] key, long counter, int length, Hmac algorithm)
    {
        Mac mac = getHmac(algorithm);
        try
        {

            byte[] buffer = getBuffer(counter, mac);

            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "RAW");
            mac.init(secretKeySpec);
            mac.update(buffer, 0, 8);
            mac.doFinal(buffer, 0);

            int offset = buffer[buffer.length - 1] & 0xf;


            int binary = ((buffer[offset] & 0x7f) << 24)
                    | ((buffer[offset + 1] & 0xff) << 16)
                    | ((buffer[offset + 2] & 0xff) << 8)
                    | (buffer[offset + 3] & 0xff);

            int result = binary % getDiv(length);

            StringBuilder sb = new StringBuilder(Integer.toString(result));
            while (sb.length() < length)
            {
                sb.insert(0, '0');
            }
            return sb.toString();

        }
        catch (InvalidKeyException e)
        {
            throw new IllegalStateException("Cannot find definition for " + mac.getAlgorithm() + ".", e);
        }
        catch (ShortBufferException e)
        {
            throw new IllegalArgumentException("Buffer is not aligned with " + mac.getAlgorithm() + "'s length.", e);
        }

    }

    private static byte[] getBuffer(long counter, Mac mac)
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

    public static Mac getHmac(Hmac hmac)
    {
        try
        {
            return Mac.getInstance("Hmac" + hmac.name().toUpperCase());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Cannot find definition for HmacSHA1");
        }
    }

    private static int getDiv(int length)
    {
        if (length == 6)
        {
            return 1_000_000;
        }
        else if( length == 7)
        {
            return 10_000_000;
        }
        else if (length == 8)
        {
            return 100_000_000;
        }
        else {
           return 1_000_000;
        }
    }
}
