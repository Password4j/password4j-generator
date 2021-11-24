package com.password4j.generator;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.Test;


public class HOTPGeneratorTest
{

    private final byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    public void test()
    {
        System.out.println(new HOTPGenerator().generate(secret, 0, 6));
    }


}
