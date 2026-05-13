package org.example;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.SM2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class Sender {

    private BigInteger sk;
    private ECPoint pk;

    private SM2KeyPair keyPair;
    public Sender(){
        keyPair = KeyGenerator.generateKeyPair();
        sk = keyPair.getPrivateKey();
        pk = keyPair.getPublicKey();
        log.info("商家公钥：{}" , HexUtil.encodeHexStr(pk.getEncoded(false)));
        log.info("商家私钥：{}" , HexUtil.encodeHexStr(sk.toByteArray()));
    }

    public ECPoint getPk() {
        return pk;
    }

    /**
     * 一重加密
     * */
    public Capsule enCapsulate(byte[] src){

        String rHex = SmUtil.sm3(keyPair.getPriHexInSoft()); //r = hash(skA)
        log.debug("r=hash(skA) : {}", rHex);
        BigInteger r = new BigInteger(rHex.getBytes());
        SM2Curve sm2 = SM2Curve.Instance();
        ECPoint P = sm2.ecc_point_g;

        ECPoint C1 = P.multiply(r); //C1 = rP
        log.debug("C1 = r*P : {}", HexUtil.encodeHexStr(C1.getEncoded(false)));
        ECPoint rpkA = pk.multiply(r); //rpkA = (xA, yA)
        //rpkA.getXCoord().getEncoded() + rpkA.getYCoord().getEncoded()
        ArrayUtil.addAll(rpkA.getXCoord().getEncoded(), rpkA.getYCoord().getEncoded());
        log.debug("rpkA = (xA,yA) : {}", HexUtil.encodeHexStr(rpkA.getEncoded(false)));
        //byte[] xA_yA = ArrayUtil.addAll(rpkA.getXCoord().getEncoded(), rpkA.getYCoord().getEncoded());
        String tHex = SmUtil.sm3(HexUtil.encodeHexStr(rpkA.getEncoded(false))); // t = H1(rpkA)
        log.debug("t = H1(r*pkA) : " + tHex);

        BigInteger C2 = new BigInteger(src).xor(new BigInteger(tHex.getBytes())); // C2 = M xor t
        log.debug("C2 = M xor t : {}", HexUtil.encodeHexStr(C2.toByteArray()));
        return new Capsule(C1, C2, null);
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
        BigInteger M = C2.xor(new BigInteger(tHex2.getBytes()));
        return M.toByteArray();
    }

    /**
     * 生成重加密密钥, 以及订单确认claim
     * */
    public Map<String,Object> generateReKey(ECPoint pkB, String orderID){
        //String alpha = "sign";
        String rHex = SmUtil.sm3(keyPair.getPriHexInSoft()); //r = hash(skA)
        BigInteger r = new BigInteger(rHex.getBytes());
        ECPoint rpkA = pk.multiply(r); //rpkA = (xA, yA)
        ECPoint rpkB = pkB.multiply(r);

        SM2 sm2 = new SM2(sk.toByteArray(), null);
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
        BigInteger rkAB = (new BigInteger(h1_rpkA.getBytes())).xor( new BigInteger(h1_rpkB.getBytes()) );
        Map map = new HashMap<>();
        map.put("rkAB", rkAB);
        map.put("Claim", claim);
        return map;
    }
}
