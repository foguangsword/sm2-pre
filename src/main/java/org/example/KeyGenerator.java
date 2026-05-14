package org.example;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

public class KeyGenerator {
    public static SM2KeyPair generateKeyPair(){
        SM2Curve sm2 = SM2Curve.Instance();
        AsymmetricCipherKeyPair key = null;
        while(true) {  //这里保证私钥是个32字节的，只保留最高字节非零的私钥
            key = sm2.ecc_key_pair_generator.generateKeyPair();
            BigInteger D = ((ECPrivateKeyParameters) key.getPrivate()).getD();
            if(BigIntegers.asUnsignedByteArray(D).length == 32){
                break;
            }
        }
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
        BigInteger privateKey = ecpriv.getD();
        ECPoint publicKey = ecpub.getQ();
        SM2KeyPair keyPair = new SM2KeyPair();
        keyPair.setPublicKey(publicKey);
        keyPair.setPrivateKey(privateKey);
        return keyPair;
    }
}
