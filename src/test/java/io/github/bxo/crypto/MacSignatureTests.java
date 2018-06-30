package io.github.bxo.crypto;


import org.junit.Test;

import java.time.Instant;

import static io.github.bxo.crypto.MacSignature.computeSignature;

public class MacSignatureTests {

    @Test
    public void testMacSign(){
        System.out.println(computeSignature("GET", Instant.now().getEpochSecond(), "/test?para=foo", "mac secret"));
    }


}
