package com.password4j.generator;

import com.password4j.types.Hmac;


public class HOTPGenerator extends OTPGenerator
{
    public static String generate(byte[] key, long counter, int length)
    {
        return generate(key, counter, length, Hmac.SHA1);
    }








}
