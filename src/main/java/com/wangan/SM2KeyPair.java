package com.wangan;

import cn.hutool.core.util.HexUtil;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class SM2KeyPair {
    BigInteger privateKey ;
    ECPoint publicKey ;

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ECPoint publicKey) {
        this.publicKey = publicKey;
    }


    //HardPubKey:3059301306072A8648CE3D020106082A811CCF5501822D03420004+X+Y
    //SoftPubKey:04+X+Y
    public String getPubHexInSoft(){
        return HexUtil.encodeHexStr(publicKey.getEncoded(false));
    }
    /*public String getPubHexInHard(){
        return SecurityTestAll.SM2PubHardKeyHead +Util.byteToHex(publicKey.getEncoded(false));
    }*/
    public String getPriHexInSoft(){
        return HexUtil.encodeHexStr(privateKey.toByteArray());
    }
}
