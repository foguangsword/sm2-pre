package org.example.test;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.BCUtil;
import cn.hutool.crypto.asymmetric.SM2;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class SignTest {
    public static void main(String[] args) {
        //指定的私钥
        String privateKeyHex = "1ebf8b341c695ee456fd1a41b82645724bc25d79935437d30e7e4b0a554baa5e";
        //需要加密的明文,得到明文对应的字节数组
        byte[] dataBytes = "我是一段测试aaaa".getBytes();
        ECPrivateKeyParameters privateKeyParameters = BCUtil.toSm2Params(privateKeyHex);
        //创建sm2 对象
        SM2 sm2 = new SM2(privateKeyParameters, null);
        //这里需要手动设置，sm2 对象的默认值与我们期望的不一致 , 使用明文编码
        sm2.usePlainEncoding();
        //sm2.setMode(SM2Engine.Mode.C1C2C3);
        byte[] sign = sm2.sign(dataBytes, null);
        System.out.println("数据: " + HexUtil.encodeHexStr(dataBytes));
        System.out.println("签名: " + HexUtil.encodeHexStr(sign));

        verifyTest();
    }

    public static void verifyTest() {
        //指定的公钥
        String publicKeyHex = "04db9629dd33ba568e9507add5df6587a0998361a03d3321948b448c653c2c1b7056434884ab6f3d1c529501f166a336e86f045cea10dffe58aa82ea13d7253763";
        //需要加密的明文,得到明文对应的字节数组
        byte[] dataBytes = "我是一段测试aaaa".getBytes();
        //签名值
        String signHex = "2881346e038d2ed706ccdd025f2b1dafa7377d5cf090134b98756fafe084dddbcdba0ab00b5348ed48025195af3f1dda29e819bb66aa9d4d088050ff148482a1";
        //这里需要根据公钥的长度进行加工
        if (publicKeyHex.length() == 130) {
            //这里需要去掉开始第一个字节 第一个字节表示标记
            publicKeyHex = publicKeyHex.substring(2);
        }
        String xhex = publicKeyHex.substring(0, 64);
        String yhex = publicKeyHex.substring(64, 128);
        ECPublicKeyParameters ecPublicKeyParameters = BCUtil.toSm2Params(xhex, yhex);
        //创建sm2 对象
        SM2 sm2 = new SM2(null, ecPublicKeyParameters);
        //这里需要手动设置，sm2 对象的默认值与我们期望的不一致 , 使用明文编码
        sm2.usePlainEncoding();
        sm2.setMode(SM2Engine.Mode.C1C2C3);
        boolean verify = sm2.verify(dataBytes, HexUtil.decodeHex(signHex));
        System.out.println("数据: " + HexUtil.encodeHexStr(dataBytes));
        System.out.println("验签结果: " + verify);
    }
}
