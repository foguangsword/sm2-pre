package org.example;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

@Slf4j
public class Receiver {
    private BigInteger sk;
    private ECPoint pk;

    private SM2KeyPair keyPair;
    public Receiver(){
        keyPair = KeyGenerator.generateKeyPair();
        sk = keyPair.getPrivateKey();
        pk = keyPair.getPublicKey();
        log.info("买家公钥：{}" , HexUtil.encodeHexStr(pk.getEncoded(false)));
        log.info("买家私钥：{}" , HexUtil.encodeHexStr(sk.toByteArray()));
    }

    public ECPoint getPk() {
        return pk;
    }

    public byte[] deCapsulate(Capsule reCapsule, Claim claim){
        ECPoint C1s = reCapsule.getC1();
        BigInteger C2s = reCapsule.getC2();
        ECPoint skBC1s = C1s.multiply(sk); //skB*C1'
        String h1_skBC1s = SmUtil.sm3(HexUtil.encodeHexStr(skBC1s.getEncoded(false)) + claim.toString()); // H1(skB*C1'||alpha)
        BigInteger Ms = C2s.xor(new BigInteger(h1_skBC1s.getBytes()));
        //System.out.println(new String(Ms.toByteArray()));
        return Ms.toByteArray();
    }
}
