package com.password4j.generator;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;

import javax.crypto.Mac;

import com.password4j.types.Hmac;


public class TOTPGenerator extends OTPGenerator
{

    public static String generate(byte[] key, Instant instant, Duration duration,  int length, Hmac algorithm)
    {
        return generate(key, instant.toEpochMilli() / duration.toMillis(), length, algorithm);
    }





}
