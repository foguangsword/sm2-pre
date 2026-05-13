package org.example;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SM4;
import lombok.extern.slf4j.Slf4j;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

@Slf4j
public class Test {

    public static void main(String[] args) throws Exception{
        //0、初始化
        Sender sender = new Sender();
        Receiver receiver = new Receiver();
        Proxy proxy = new Proxy();

        //1、sender初始加密，并将密文存放在proxy
        //String src = "LoveLoveLoveLove"; //128bit

        byte[] srcbyte = new byte[16];
        SecureRandom random = new SecureRandom();  //密码学安全的128bit伪随机数
        random.nextBytes(srcbyte);
        //String src = new String(srcbyte, "utf-8");

        log.info("对称密钥原文hex : {}", HexUtil.encodeHexStr(srcbyte));
        Capsule capsule = sender.enCapsulate(srcbyte);
        proxy.setCapsule(capsule);
        log.info("一重加密Capsule : {}", capsule.toString());
        //一重加密sender解密,测试
        byte[] deSrc = sender.deCapsulate(capsule);
        log.info("一重加密解密：{}", HexUtil.encodeHexStr(deSrc));

        //2、sender生成重加密密钥, 给到服务端
        String orderID = "423549003"; //订单号
        //BigInteger rkAB = sender.generateReKey(receiver.getPk(), orderID);
        Map map = sender.generateReKey(receiver.getPk(), orderID);
        BigInteger rkAB = (BigInteger)map.get("rkAB");
        Claim claim = (Claim)map.get("Claim");
        proxy.setRk(rkAB);
        proxy.setClaim(claim);
        log.info("重加密密钥rk：{}", HexUtil.encodeHexStr(rkAB.toByteArray()));

        //3、proxy二重加密
        proxy.reEnCapsulate();

        //4、二重加密解密
        byte[] text = receiver.deCapsulate(proxy.getReCapsule(), proxy.getClaim());
        log.info("接收方用sk解密,得到对称密钥：{}", HexUtil.encodeHexStr(text));

        symmetricCryptoTest(text);
    }

    public static void symmetricCryptoTest(byte[] key) {
        String message = "闪电贷是一种关于DeFi无抵押贷款的新思路，所有操作都在一笔交易（一个区块）中完成，它允许借款人无需抵押资产即可实现借贷（但需支付额外较少费用）。因为代码保证在一定时间内（以太坊大约是13秒）偿还借款，如果资金没有返还，那么交易会被还原，即撤消之前执行的所有操作，从而确保协议和资金的安全。";
        SM4 sm4 = SmUtil.sm4(key);
        String encryptHex = sm4.encryptHex(message, "utf-8");
        log.info("sm4算法对称加密明文，得到16进制密文：{}", encryptHex);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.charset("utf-8"));
        log.info("sm4解密16进制密文，得到明文：{}", decryptStr);
    }
}