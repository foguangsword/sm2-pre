package com.wangan;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.symmetric.SM4;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

@Slf4j
public class Test {
    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            // 命令行传入指定测试向量
            String hex = args[0];
            if (hex.length() != 32) {
                log.error("输入必须是 32 字符 hex（16 字节），当前长度: {}", hex.length());
                return;
            }
            byte[] srcbyte = HexUtil.decodeHex(hex);
            runSingleTest(srcbyte, "args[\"" + hex + "\"]");
        } else {
            // 默认跑全部测试向量
            log.info("========== 测试向量 1: 最高字节 0x00（最容易触发 bitLength/8 < 16）==========");
            byte[] case1 = new byte[16];
            for (int i = 0; i < 16; i++) case1[i] = (byte) i; // 0x00, 0x01, ..., 0x0F
            runSingleTest(case1, "case1_0x00");

            log.info("========== 测试向量 2: 最高字节 0x7F（bitLength < 128）==========");
            byte[] case2 = new byte[16];
            case2[0] = 0x7F;
            for (int i = 1; i < 16; i++) case2[i] = (byte) (i + 1);
            runSingleTest(case2, "case2_0x7F");

            log.info("========== 测试向量 3: 最高字节 0x80（bitLength = 128）==========");
            byte[] case3 = new byte[16];
            case3[0] = (byte) 0x80;
            for (int i = 1; i < 16; i++) case3[i] = (byte) (i + 1);
            runSingleTest(case3, "case3_0x80");

            log.info("========== 测试向量 4: 全 0xFF ==========");
            byte[] case4 = new byte[16];
            for (int i = 0; i < 16; i++) case4[i] = (byte) 0xFF;
            runSingleTest(case4, "case4_0xFF");

            log.info("========== 测试向量 5: SecureRandom 随机（跑 5 次）==========");
            SecureRandom random = new SecureRandom();
            for (int i = 0; i < 5; i++) {
                byte[] case5 = new byte[16];
                random.nextBytes(case5);
                runSingleTest(case5, "case5_random_" + i);
            }
        }
    }

    public static void runSingleTest(byte[] srcbyte, String caseName) throws Exception {
        log.info("[{}] 对称密钥原文hex : {}", caseName, HexUtil.encodeHexStr(srcbyte));

        Sender sender = new Sender();
        Receiver receiver = new Receiver();
        Proxy proxy = new Proxy();

        Capsule capsule = sender.enCapsulate(srcbyte);
        proxy.setCapsule(capsule);

        // 一重加密解密自测
        byte[] deSrc = sender.deCapsulate(capsule);
        boolean encDecOk = java.util.Arrays.equals(srcbyte, deSrc);
        log.info("[{}] 一重加密解密结果 : {} ({})", caseName, HexUtil.encodeHexStr(deSrc), encDecOk ? "PASS" : "FAIL");
        if (!encDecOk) {
            log.error("[{}] 一重加密解密失败，终止后续测试", caseName);
            return;
        }

        // 生成重加密密钥
        String orderID = "423549003";
        Map map = sender.generateReKey(receiver.getPk(), orderID);
        BigInteger rkAB = (BigInteger) map.get("rkAB");
        Claim claim = (Claim) map.get("Claim");
        proxy.setRk(rkAB);
        proxy.setClaim(claim);
        log.info("[{}] 重加密密钥rk : {}", caseName, HexUtil.encodeHexStr(BigIntegers.asUnsignedByteArray(16, rkAB)));

        // Proxy 二重加密
        proxy.reEnCapsulate();

        // 二重加密解密
        byte[] text = receiver.deCapsulate(proxy.getReCapsule(), proxy.getClaim());
        boolean reEncDecOk = java.util.Arrays.equals(srcbyte, text);
        log.info("[{}] 接收方解密结果 : {} ({})", caseName, HexUtil.encodeHexStr(text), reEncDecOk ? "PASS" : "FAIL");
        if (!reEncDecOk) {
            log.error("[{}] 接收方解密失败", caseName);
            return;
        }

        // SM4 对称加解密验证
        symmetricCryptoTest(text, caseName);

        log.info("[{}] 全部通过 ============================================\n", caseName);
    }

    public static void symmetricCryptoTest(byte[] key, String caseName) {
        String message = "闪电贷是一种关于DeFi无抵押贷款的新思路，所有操作都在一笔交易（一个区块）中完成，它允许借款人无需抵押资产即可实现借贷（但需支付额外较少费用）。因为代码保证在一定时间内（以太坊大约是13秒）偿还借款，如果资金没有返还，那么交易会被还原，即撤消之前执行的所有操作，从而确保协议和资金的安全。";
        SM4 sm4 = SmUtil.sm4(key);
        String encryptHex = sm4.encryptHex(message, "utf-8");
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.charset("utf-8"));
        boolean sm4Ok = message.equals(decryptStr);
        log.info("[{}] SM4 加解密 : {}", caseName, sm4Ok ? "PASS" : "FAIL");
    }
}
