package org.example;

import cn.hutool.core.util.HexUtil;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Capsule {
    private ECPoint C1;
    private BigInteger C2;
    private BigInteger C3;

    public Capsule(ECPoint C1, BigInteger C2, BigInteger C3){
        this.C1 = C1;
        this.C2 = C2;
        this.C3 = C3;
    }

    public ECPoint getC1() {
        return C1;
    }

    public void setC1(ECPoint c1) {
        C1 = c1;
    }

    public BigInteger getC2() {
        return C2;
    }

    public void setC2(BigInteger c2) {
        C2 = c2;
    }

    public BigInteger getC3() {
        return C3;
    }

    public void setC3(BigInteger c3) {
        C3 = c3;
    }

    public String toString(){
        String C1Hex = HexUtil.encodeHexStr(C1.getEncoded(false));
        String C2Hex = HexUtil.encodeHexStr(C2.toByteArray());
        return C1Hex + C2Hex;
    }
}
