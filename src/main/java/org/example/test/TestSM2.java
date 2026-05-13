package org.example.test;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.CharsetUtil;
import cn.hutool.core.util.HexUtil;

public class TestSM2 {
    public static void main(String[] args) {
        String encode = "B6FZL+rwptKfNBgg5jEBxbTaKjA0nsi2lZkDkl9FLLjVQRbNGr7lBp0geyGGj04Mck8oPj7TA4MmQrfvbd2rCE5xmC4bpcFYXTmIZJMXsvgf7FhOBdqA5zyNYSCuCopK/fyvgh/8kcwaqTO6PH/UissMFYFRe6ieHMpNYZjWeKPS4RRxFZUqKqptaueX88y+r6octceJuCs3Zo/RZoM3OzZbHW7XVae9agEH9VTFvBAFPQ6Abd5Y5NIPdfiApjc4fvaBkhEmiuCGElAbJuXwkw==";
        String decodeStr = Base64.decodeStr(encode);
        System.out.println(decodeStr);
        String hex = HexUtil.encodeHexStr(decodeStr, CharsetUtil.CHARSET_UTF_8);

        System.out.println(hex);
    }
}
