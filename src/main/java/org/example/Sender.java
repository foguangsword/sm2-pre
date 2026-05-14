package org.example;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.SM2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class Sender {
    private BigInteger sk;
    private ECPoint pk;
    private SM2KeyPair keyPair;
    private BigInteger r;

    public Sender() {
        keyPair = KeyGenerator.generateKeyPair();
        sk = keyPair.getPrivateKey();
        pk = keyPair.getPublicKey();
        log.info("商家公钥：{}" , HexUtil.encodeHexStr(pk.getEncoded(false)));
        log.info("商家私钥：{}" , HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(32, sk)));
    }

    public ECPoint getPk() {
        return pk;
    }

    /**
     * 一重加密
     * */
    public Capsule enCapsulate(byte[] src){
        BigInteger i = KeyGenerator.generateKeyPair().privateKey;
        String rHex = SmUtil.sm3( HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(32, i)));
        log.debug("r=hash(i) : {}", rHex);
        r = new BigInteger(1, HexUtil.decodeHex(rHex)); //r = hash(i)
        SM2Curve sm2 = SM2Curve.Instance();
        ECPoint P = sm2.ecc_point_g;

        ECPoint C1 = P.multiply(r); //C1 = rP
        log.debug("C1 = r*P : {}", HexUtil.encodeHexStr(C1.getEncoded(false)));
        ECPoint rpkA = pk.multiply(r); //rpkA = (xA, yA)
        //rpkA.getXCoord().getEncoded() + rpkA.getYCoord().getEncoded()
        // ArrayUtil.addAll(rpkA.getXCoord().getEncoded(), rpkA.getYCoord().getEncoded());
        log.debug("rpkA = (xA,yA) : {}", HexUtil.encodeHexStr(rpkA.getEncoded(false)));
        //byte[] xA_yA = ArrayUtil.addAll(rpkA.getXCoord().getEncoded(), rpkA.getYCoord().getEncoded());
        String tHex = SmUtil.sm3(HexUtil.encodeHexStr(rpkA.getEncoded(false))); // t = H1(rpkA)
        log.debug("t = H1(r*pkA) : " + tHex);
        //src 16字节，而HexUtil.decodeHex(tHex)是sm3解码后是32字节，所以需要对齐
        /*byte[] tBytes = HexUtil.decodeHex(tHex);
        byte[] tTruncated = Arrays.copyOf(tBytes, src.length); // 取前 16 字节
        BigInteger C2 = new BigInteger(1, src).xor(new BigInteger(1, tTruncated));*/

        BigInteger C2 = new BigInteger(1, src).xor(new BigInteger(1, HexUtil.decodeHex(tHex))); // C2 = M xor t
        log.debug("C2 = M xor t : {}", HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(32, C2)));
        String h1_xA_M_yA = SmUtil.sm3( HexUtil.encodeHexStr(rpkA.getXCoord().getEncoded())
                + HexUtil.encodeHexStr(src)
                + HexUtil.encodeHexStr(rpkA.getYCoord().getEncoded()) );
        log.debug("C3 = hash(xA || M || yA) : {}", h1_xA_M_yA);
        BigInteger C3 = new BigInteger(1, HexUtil.decodeHex(h1_xA_M_yA)); //C3 = hash(xA || M || yA)
        String h1_M_C1_C3 = SmUtil.sm3(HexUtil.encodeHexStr(src)
                + HexUtil.encodeHexStr(C1.getEncoded(false))
                + h1_xA_M_yA);
        log.debug("C4 = hash(M || C1 || C3) : {}", h1_M_C1_C3);
        BigInteger C4 = new BigInteger(1, HexUtil.decodeHex(h1_M_C1_C3));
        Capsule capsule = new Capsule(C1, C2, C3, C4);
        return capsule;
    }

    /**
     * 一重加密解密
     * */
    public byte[] deCapsulate(Capsule capsule){
        ECPoint C1 = capsule.getC1();
        BigInteger C2 = capsule.getC2();
        ECPoint S = C1.multiply(sk); //S = skA*C1 = skA*r*P = r*pkA = (xA, yA)
        log.debug("r*pkA = (xA, yA) : {}", HexUtil.encodeHexStr(S.getEncoded(false)));
        //byte[] tmp = ArrayUtil.addAll(S.getXCoord().getEncoded(), S.getYCoord().getEncoded()); // xA||yA
        String tHex2 = SmUtil.sm3(HexUtil.encodeHexStr(S.getEncoded(false)));
        log.debug("t = H1(skA*C1) : {}", tHex2);
        BigInteger M = C2.xor( new BigInteger(1, HexUtil.decodeHex(tHex2)) );
        return BigIntegers.asUnsignedByteArray(16, M);
    }

    /**
     * 生成重加密密钥, 以及订单确认claim
     * */
    public Map<String,Object> generateReKey(ECPoint pkB, String orderID){
        //String rHex = SmUtil.sm3(keyPair.getPriHexInSoft()); //r = hash(skA)
        //BigInteger r = new BigInteger(1, HexUtil.decodeHex(rHex));
        ECPoint rpkA = pk.multiply(r); //rpkA = (xA, yA)
        ECPoint rpkB = pkB.multiply(r);

        SM2 sm2 = new SM2(BigIntegers.asUnsignedByteArray(32, sk), null);
        long timestamp = System.currentTimeMillis();
        String sign = sm2.signHex(HexUtil.encodeHexStr(orderID + timestamp));
        //String claim = orderID + System.currentTimeMillis() + sign;
        Claim claim = new Claim();
        claim.setOrderID(orderID);
        claim.setTimestamp(timestamp);
        claim.setSign(sign);
        claim.setIssuer(HexUtil.encodeHexStr(pk.getEncoded(false)));
        String h1_rpkA = SmUtil.sm3(HexUtil.encodeHexStr(rpkA.getEncoded(false))); // t = H1(rpkA)
        String h1_rpkB = SmUtil.sm3(HexUtil.encodeHexStr(rpkB.getEncoded(false)) + claim.toString()); //H1(rpkB || alpha)
        //rkAB = H1(rpkA) xor H1(rpkB||alpha)
        BigInteger rkAB = (new BigInteger(1, HexUtil.decodeHex(h1_rpkA)))
                            .xor( new BigInteger(1, HexUtil.decodeHex(h1_rpkB)) );
        Map map = new HashMap<>();
        map.put("rkAB", rkAB);
        map.put("Claim", claim);
        return map;
    }
}
