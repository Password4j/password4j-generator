package com.password4j.generator;

import javax.crypto.Mac;


public abstract class OTPGenerator
{

    public abstract String generate(byte[] key, long counter, int length);

    public abstract Mac getHmac();
}
