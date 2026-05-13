package org.example;

import cn.hutool.json.JSONUtil;

public class Claim {

    private String orderID;

    private long timestamp;

    private String issuer;

    private String sign;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }



    public String getOrderID() {
        return orderID;
    }

    public void setOrderID(String orderID) {
        this.orderID = orderID;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getSign() {
        return sign;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }

    public String toString() {
        return JSONUtil.toJsonStr(this);
    }
}
