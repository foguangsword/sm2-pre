# SM2-PRE：基于国密算法的代理重加密 Java 实现

**Proxy Re-Encryption based on Chinese National Cryptographic Standard SM2**

------

## 中文

### 项目简介

本项目实现了一套基于**国密 SM2 椭圆曲线算法**的**代理重加密（Proxy Re-Encryption, PRE）**方案，并结合 SM3 哈希与 SM4 对称加密，构成完整的国密套件加密链路。

代理重加密的核心价值在于：数据拥有者（Alice）可以授权代理服务器将其密文**转换**为接收方（Bob）可解密的形式，而代理服务器**全程无法获知明文**，实现了密码学意义上的安全数据共享，适用于区块链数据受控共享、联盟链权限管理等场景。

本项目的理论依据来自：

- 《基于代理重加密的区块链数据受控共享方案》，贵州大学，郭庆、田有亮、万良
- 《基于国密算法的秘密文件的加、解密方法及保护系统》，北京航空航天大学，伍前红

------

### 密码学原理

#### 标准 SM2 加密流程（简化）

```
KeyGen:   skA ∈ [1, n-1]（随机）,  pkA = skA · P
Encrypt:  r ← random
          C1 = r · P
          t  = H(r · pkA)
          C2 = M ⊕ t
          C3 = H(x_A ‖ M ‖ y_A)   （完整性校验）
Decrypt:  t  = H(skA · C1)
          M  = C2 ⊕ t
```

#### PRE 扩展：重加密密钥与转换

```
ReKeyGen(skA, pkB):
    r    ← random（每次加密独立生成）
    rkAB = H(r · pkA) ⊕ H(r · pkB ‖ α)
    α    = Sign_skA(pkB ‖ order_id)   （授权凭证，Proxy 可验证）

ReEncrypt(C, rkAB):
    C2'  = rkAB ⊕ C2

Decrypt_B(C', skB):
    M    = C2' ⊕ H(skB · C1 ‖ α)
         = H(r·pkA) ⊕ H(r·pkB‖α) ⊕ (M ⊕ H(r·pkA)) ⊕ H(r·pkB‖α)
         = M   ✓
```

完整正确性证明见 [PROOF.md](https://claude.ai/chat/PROOF.md)。

------

### 整体流程

```
Alice                       Proxy                        Bob
  │                           │                           │
  │── enCapsulate(M) ────────►│  存储密文 C=(C1,C2,C3)    │
  │                           │                           │
  │── generateReKey(pkB) ────►│  验证授权参数 α            │
  │   rkAB, α                 │                           │
  │                           │── reEncapsulate() ───────►│
  │                           │   C'=(C1, C2'=rkAB⊕C2)   │
  │                           │                           │
  │                           │              deCapsulate()│
  │                           │              M = C2'⊕H(skB·C1‖α)
```

PRE 仅用于安全交换对称密钥 K（128 bit），大文件加密由 **SM4** 完成，兼顾性能与安全。

------

### 模块结构

```
src/main/java/
├── SM2Curve.java          # SM2 国密曲线参数（p, a, b, n, Gx, Gy）
├── SM2KeyPair.java        # 密钥对封装
├── KeyGenerator.java      # 密钥对生成
├── Capsule.java           # 密文封装（C1, C2, C3）
├── Sender.java            # 数据拥有者：加密、生成重加密密钥
├── Receiver.java          # 数据接收方：解密
├── Proxy.java             # 代理服务器：重加密转换
└── Test.java              # 完整链路测试（含 SM4 对称加密验证）
```

------

### 快速开始

**环境要求**：JDK 8+，Maven 3.x

```bash
git clone https://github.com/<your-username>/sm2-pre.git
cd sm2-pre
mvn compile
mvn exec:java -Dexec.mainClass="org.example.Test"
```

**依赖**（见 `pom.xml`）：

| 依赖               | 版本    | 用途                      |
| ------------------ | ------- | ------------------------- |
| `bcprov-jdk15to18` | 1.69    | BouncyCastle，SM2/EC 运算 |
| `hutool-all`       | 5.8.16  | SM3/SM4 封装              |
| `lombok`           | 1.18.24 | 样板代码简化              |

------

### 预期输出

```
[INFO] 对称密钥原文hex       : e48c1582d860fcc7a9059917ca39f4ec
[INFO] 一重加密解密           : e48c1582d860fcc7a9059917ca39f4ec   ✓
[INFO] 接收方解密，得到对称密钥 : e48c1582d860fcc7a9059917ca39f4ec   ✓
[INFO] SM4解密明文            : 闪电贷是一种关于DeFi无抵押贷款的新思路……        ✓
```

------

### 已知局限性（Known Limitations）

本项目以下几点在生产场景中需要进一步处理：

| 问题                   | 说明                                                   |
| ---------------------- | ------------------------------------------------------ |
| 无 C3/C4 完整性校验    | 当前实现省略了密文完整性验证字段，生产环境应补充       |
| `α` 授权参数为简化实现 | 当前为占位符，完整方案应使用 `Sign_skA(pkB ‖ orderId)` |
| 不支持变长明文         | 设计上仅用于固定长度对称密钥的安全传输                 |

------

### 参考资料

- 郭庆等，《基于代理重加密的区块链数据受控共享方案》，贵州大学
- [国家密码管理局 SM2 标准文档](http://www.sca.gov.cn/)
- [BouncyCastle 官方文档](https://www.bouncycastle.org/documentation.html)
- [goRecrypt — Go 版 PRE 参考实现](https://github.com/SherLzp/goRecrypt)

------

## English

### Overview

This project implements a **Proxy Re-Encryption (PRE)** scheme built on top of China's national cryptographic standard **SM2** (elliptic curve), combined with **SM3** (hash) and **SM4** (symmetric encryption) to form a complete GM/T cryptographic pipeline.

The key property of PRE: the data owner (Alice) can delegate the proxy server to transform her ciphertext into a form decryptable by Bob — without the proxy ever learning the plaintext. This enables cryptographically secure data sharing, applicable to blockchain data access control and permissioned ledger scenarios.

------

### Cryptographic Design

#### SM2 Encryption (simplified)

```
KeyGen:   skA ∈ [1, n-1] random,  pkA = skA · P
Encrypt:  r ← random
          C1 = r · P
          t  = H(r · pkA)
          C2 = M ⊕ t
          C3 = H(xA ‖ M ‖ yA)   (integrity check)
Decrypt:  t  = H(skA · C1)
          M  = C2 ⊕ t
```

#### PRE Extension

```
ReKeyGen(skA, pkB):
    r    ← random (fresh per encryption)
    rkAB = H(r · pkA) ⊕ H(r · pkB ‖ α)
    α    = Sign_skA(pkB ‖ orderId)   (proxy-verifiable authorization)

ReEncrypt:  C2' = rkAB ⊕ C2

Decrypt_B:  M   = C2' ⊕ H(skB · C1 ‖ α)  =  M  ✓
```

#### Correctness Proof (sketch)

```
C2' ⊕ H(skB · C1 ‖ α)
  = [H(r·pkA) ⊕ H(r·pkB‖α) ⊕ C2] ⊕ H(skB·r·P‖α)
  = H(r·pkA) ⊕ H(r·pkB‖α) ⊕ (M ⊕ H(r·pkA)) ⊕ H(r·pkB‖α)
  = M  ✓
```

Note: `skB · C1 = skB · r · P = r · skB · P = r · pkB`, so Bob can independently reconstruct `H(r · pkB ‖ α)`.

------

### Architecture

```
Sender (Alice)
  enCapsulate(M)    → Capsule C = (C1, C2, C3)  →  Proxy stores C
  generateReKey(pkB) → rkAB, α                  →  Proxy receives rkAB

Proxy
  reEncapsulate()   → C' = (C1, C2' = rkAB ⊕ C2) → Receiver gets C'

Receiver (Bob)
  deCapsulate(C', skB) → M  ✓
```

PRE is used only to securely transfer a 128-bit symmetric key. Bulk data encryption is handled by **SM4** for efficiency.

------

### Getting Started

**Requirements**: JDK 8+, Maven 3.x

```bash
git clone https://github.com/<your-username>/sm2-pre.git
cd sm2-pre
mvn compile
mvn exec:java -Dexec.mainClass="org.example.Test"
```

------

### Known Limitations

| Issue                       | Note                                                         |
| --------------------------- | ------------------------------------------------------------ |
| No C3/C4 integrity check    | Omitted for simplicity; should be added for production use   |
| `α` is a placeholder        | Full scheme requires `Sign_skA(pkB ‖ orderId)`               |
| Fixed-length plaintext only | Designed for symmetric key transport, not arbitrary messages |

------

