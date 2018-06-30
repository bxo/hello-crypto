package io.github.bxo.crypto;


import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ECKeyTests {

    @Test
    public void testBigIntegers(){
        String s = "e1d9f1ed2e65f09f6ce0893baf5e8e31e6ae82ea8c3592335be906d38dee";
        testBigInteger(s);

        String s1 = "7fd9f1ed2e65f09f6ce0893baf5e8e31e6ae82ea8c3592335be906d38dee";
        testBigInteger(s1);
    }

    @Test
    public void testSign() throws IOException, NoSuchAlgorithmException {
        String s = "ffd9f1ed2e65f09f6ce0893baf5e8e31e6ae82ea8c3592335be906d38dee";
        byte[] privateKey = getDigest(s);
        BigInteger privateBigInteger = new BigInteger(privateKey);

        String content = "Hello";
        byte[] digest = getDigest(content);

        byte[] sig = ECKey.doSign(digest,privateBigInteger).encodeToDER();

        byte[] pubKey = ECKey.publicKeyFromPrivate(privateBigInteger,true);
        boolean verify = ECKey.verify(digest, ECKey.ECDSASignature.decodeFromDER(sig),pubKey);
        System.out.println(verify);
    }

    private byte[] getDigest(String content) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance( "SHA-256" );
        // Change this to UTF-16 if needed
        md.update(content.getBytes( StandardCharsets.UTF_8 ) );
        byte[] digest = md.digest();
        return digest;
    }


    private void testBigInteger(String s){
        byte[] bytes = Hex.decode(s);
        BigInteger v = new BigInteger(bytes);

        System.out.println(v);
        System.out.println(Hex.toHexString(v.toByteArray()));
        byte[] pubKey = ECKey.publicKeyFromPrivate(v,true);

        System.out.println(Hex.toHexString(pubKey));

    }

}
