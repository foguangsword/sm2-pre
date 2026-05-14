package org.example;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.asymmetric.SM2;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

@Slf4j
public class Proxy {
    private Capsule capsule; //一重加密密文

    private BigInteger rk;

    private Capsule reCapsule; //二重加密密文

    private Claim claim; //商家的订单确认声明

    public Claim getClaim() {
        return claim;
    }

    public void setClaim(Claim claim) {
        this.claim = claim;
    }

    public void setCapsule(Capsule capsule) {
        this.capsule = capsule;
    }

    public void setRk(BigInteger rk) {
        this.rk = rk;
    }

    public Capsule getReCapsule() {
        return reCapsule;
    }

    /**
     * 代理服务器端二重加密
     * */
    public void reEnCapsulate(){
        //先验证claim，校验商家对订单是否进行了确认
        SM2 sm2 = new SM2(null, this.claim.getIssuer());
        boolean vert = sm2.verifyHex(HexUtil.encodeHexStr(this.claim.getOrderID()+this.claim.getTimestamp()), this.claim.getSign());
        log.info("Claim值：{}", this.claim);
        log.info("Claim验证结果：{}" , vert);

        //SM2 sm2 = new SM2(null, pkA);
        ECPoint C1s = capsule.getC1(); //C1' = C1
        BigInteger C2 = capsule.getC2();
        BigInteger C2s = rk.xor(C2); //C2' = rkAB xor C2
        BigInteger C3s = capsule.getC3();
        BigInteger C4s = capsule.getC4();
        log.debug("C2' : {}" , HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(32, C2s)));
        reCapsule = new Capsule(C1s, C2s, C3s, C4s);
        log.info("二重加密Capsule : {}", reCapsule);
    }
}
