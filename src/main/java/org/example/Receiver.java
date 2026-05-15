package org.example;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.util.Arrays;

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
        log.info("买家私钥：{}" , HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(32, sk)));
    }

    public ECPoint getPk() {
        return pk;
    }

    public byte[] deCapsulate(Capsule reCapsule, Claim claim){
        ECPoint C1s = reCapsule.getC1();
        BigInteger C2s = reCapsule.getC2();
        BigInteger C3s = reCapsule.getC3();
        BigInteger C4s = reCapsule.getC4();
        ECPoint skBC1s = C1s.multiply(sk); //skB*C1'
        String h1_skBC1s = SmUtil.sm3(HexUtil.encodeHexStr(skBC1s.getEncoded(false)) + claim.toString()); // H1(skB*C1'||alpha)
        byte[] tBytes = HexUtil.decodeHex(h1_skBC1s);
        byte[] tTruncated = Arrays.copyOf(tBytes, 16);
        BigInteger Ms = C2s.xor(new BigInteger(1, tTruncated));

        String h4_Ms_C1s_C3s = SmUtil.sm3( HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(16, Ms))
                + HexUtil.encodeHexStr(C1s.getEncoded(false))
                + HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(32, C3s)));
        BigInteger k = new BigInteger(1, HexUtil.decodeHex(h4_Ms_C1s_C3s)); // k = H4(M'||C1'||C3')
        boolean result = k.equals(C4s);
        log.info("交付数据完整性校验结果: {}", result);
        return BigIntegers.asUnsignedByteArray(16, Ms);
    }
}
