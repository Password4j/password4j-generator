package com.password4j.generator;

import static org.junit.Assert.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.password4j.types.Hmac;


public class HOTPGeneratorTest
{

    private static final String[] TEST_VECTOR_6 = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};

    @Test
    public void test6digits()
    {
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.UTF_8);

        for(int counter = 0; counter < 10; counter++)
        {
            assertEquals(TEST_VECTOR_6[counter], HOTPGenerator.generate(secret, counter, 6, Hmac.SHA1));
        }
    }


}
