package io.github.bxo.crypto;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class MacSignature {

    public static String computeSignature(String method, long timestamp, String url, String secret) {
        try {
            String data = method + "_" + timestamp + "_" + url;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
            return new String(Base64.getEncoder().encode(mac.doFinal(data.getBytes())), "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

}