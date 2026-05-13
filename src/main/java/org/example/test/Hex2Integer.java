package org.example.test;

import cn.hutool.core.util.HexUtil;

import java.math.BigInteger;

public class Hex2Integer {
    public static void main(String[] args) {

        String p = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
        String a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
        String b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
        String n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
        String Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
        String Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";

        System.out.println(hex2int(p).toString());
        System.out.println(hex2int(a).toString());
        System.out.println(hex2int(b).toString());
        System.out.println(hex2int(n).toString());
        System.out.println(hex2int(Gx).toString());
        System.out.println(hex2int(Gy).toString());
    }

    public static BigInteger hex2int(String hex){
       // byte[] bytes = HexUtil.decodeHex(hex);
        return new BigInteger(hex, 16);
    }
}
