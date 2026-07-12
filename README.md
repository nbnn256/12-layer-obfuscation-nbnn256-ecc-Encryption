# in_nbnn256 — 封板加密综合工具 v3.5-hkfix

> 完整加密工具箱：12 层字节混淆 + Argon2id/PBKDF2 + 注册表 6 值硬件指纹 + nbnn256 可逆封板 + 8192bit 设备密钥 + ECC secp256k1 ECIES

---

## 概述

`in_nbnn_decrypted.py` 是一个 Windows 平台的纯 Python 加密工具，集成多层加密体系：

| 层级 | 算法 | 作用 |
|------|------|------|
| 内层 | 12 层字节混淆 + 1024-byte XOR | 快速混淆密文 |
| KDF | Argon2id / PBKDF2-SHA256 | 密钥派生，绑定硬件指纹 |
| 设备绑定 | DPAPI + TPM (NCrypt DPAPI-NG) | 密钥固化到本机 |
| 封板 | nbnn256（256 轮大数 + 位标记 + 字节交错） | 元数据加密保护 |
| 8192bit | R1+R2 随机对（TPM 密封 + DPAPI） | 每文件/每会话一次性 XOR pad |
| 非对称 | ECC secp256k1 ECIES (ECDH + HKDF + AES-256-GCM) | 跨机器密钥交换 |

---

## 架构

### 加密链（完整 ECC 模式）

```
明文
  → encrypt_flow (12层 + 1024-byte XOR + Argon2id)
    → cd (密文) + meta (参数)
  → XOR(R1) where R1 = _gen_8192_store() (1024 字节随机, TPM 密封)
  → _build_nbnn_output (nbnn256 加密 meta → IFON 段)
    → 文件含: 【密文】+ ---NBNN-INFO--- + IFON=
  → ecc_encrypt(wrap b_key with recipient's EC public key)
    → 【ECC密钥】段 (ECIES: ephem_der + nonce + ct, base64)
```

### 解密链（ECC 模式，逆向）

```
ECC 文件
  → 解析 【ECC密钥】→ ecc_decrypt (EC private key unwrap → b_str)
  → _parse_nbnn_output → 解 IFON (LZMA2 → deinterleave → nbnn256_decrypt → meta)
  → XOR(R1) via _read_8192_r1
  → decrypt_flow (12层逆向 + Argon2id)
  → 明文
```

---

## 加密模式

| 启动参数 | 模式 | 说明 |
|----------|------|------|
| (无参数) | 主菜单 | 4 项核心 + 2 项本机加密/解密 |
| `-hk` | 硬件密钥模式 | 8192bit 设备绑定密钥，免密码 |
| `-ecc` | ECC 模式 | secp256k1 ECIES，公钥加密私钥解密 |
| `-qq` | 直进加密 | 加密 + QQ/邮件采集 |
| `-cz` | 清指纹 | 清除注册表指纹（旧文件将失效） |

### 主菜单（无参数）

```
🔐 封板 v3.5-hkfix（8192bit设备密钥+DPAPI+文件密钥+nbnn256）
1.加密         2.解密         3.验证         4.退
5.本机加密(8192bit)  6.本机解密(自动识别)
```

- 选项 1/2：标准加密，支持追加 nbnn256，密码 TPM 缓存
- 选项 3：HMAC-SHA256 验证
- 选项 5/6：硬件绑定模式（需本机 `get_device_key()` 返回非空）

### 硬件密钥模式（-hk）

```
🔐 封板 v3.4-hk（8192bit设备密钥，仅本机可用）
1.硬件加密 2.硬件解密 3.退
```

- 使用 8192bit 设备密钥（R1+R2 pair）作为密码
- 支持追加 nbnn256

### ECC 模式（-ecc）

```
🔐 封板 v3.5-ecc（12层+ nbnn256 + secp256k1 ECIES）
1.生成密钥对 2.ECC加密 3.ECC解密 4.退
```

1. **生成密钥对**：secp256k1，私钥 TPM 密封至注册表，公钥保存 PEM
2. **ECC 加密**：指定接收方公钥 → 随机密钥 → 12层 → XOR(R1) → nbnn256 → ECIES 包装 b-key
3. **ECC 解密**：本机 TPM 私钥解 ECIES → b-key → nbnn256 → XOR(R1) → 12层逆

---

## 注册表结构

路径：`HKCU\Software\JMEncrypt`

| 键名 | 类型 | 保护 | 内容 |
|------|------|------|------|
| `SecureStore` | REG_BINARY | DPAPI | JSON: v0-v4(5硬件), rand(240bit), dk(8192bit 密钥) |
| `HkR1` | REG_BINARY | TPM (NCrypt) | 1024 字节随机 R1 |
| `HkPair` | REG_BINARY | DPAPI + XOR(pad) | R2 密钥（XOR 加密） |
| `EcKey` | REG_BINARY | TPM | EC 私钥 (DER/PKCS8) |
| `Tpm8192R2` | REG_BINARY | DPAPI | 8192bit R2 |
| `Tpm8192R1R2` | REG_BINARY | TPM | R1+R2 拼接（2048 字节） |
| `NbnnB` | REG_BINARY | TPM | nbnn256 b-key (512 char base62) |
| `PwdBox` | REG_BINARY | TPM | 最后使用的密码 |
| `INIT_FLAG` | REG_SZ | - | 初始化标记 `"1"` |

---

## 硬件指纹（注册表 6 值）

| 索引 | 来源 | 位数 | 说明 |
|------|------|------|------|
| v0 | `GetVolumeInformationA("C:\\")` | 32 | 卷序列号 |
| v1 | `HKLM\...\InstallDate` | 32 | Windows 安装时间戳 |
| v2 | `HKLM\...\BIOS\SerialNumber` | 可变 | BIOS 序列号 |
| v3 | `HKLM\...\Cryptography\MachineGuid` | 36 | 机器 GUID |
| v4 | `HKLM\...\CentralProcessor\0\ProcessorId` | 可变 | CPU 序列号 |
| rand | `_gen_master_rand()` | 240 | SHAKE-256 派生 XOR 随机位 |

所有 6 值通过 DPAPI 整体加密存储在 `SecureStore` 中。

---

## 12 层字节混淆

| # | 层名 | 方向 | 说明 |
|---|------|------|------|
| 0 | `xor` | 双向 | 全字节 XOR 参数 |
| 1 | `rol` | 可逆 | 循环左移 |
| 2 | `block_shuffle` | 可逆 | 分块随机打乱（种子依赖） |
| 3 | `reverse` | 双向 | 全数据反转 |
| 4 | `swap_nibbles` | 双向 | 半字节交换 |
| 5 | `interval_xor` | 双向 | 间隔 XOR |
| 6 | `block_reverse` | 双向 | 分块内部反转 |
| 7 | `index_xor` | 双向 | 索引 XOR |
| 8 | `group_permute` | 可逆 | 8 字节组内置换（种子依赖） |
| 9 | `arithmetic_shr` | 可逆 | 算术右移 |
| 10 | `prng_xor` | 双向 | PRNG 流 XOR（种子依赖） |
| 11 | `b64` | 双向 | Base64 编解码 |

层序、参数、种子均由 KDF 派生，层 2/8/10 使用随机子种子。

---

## KDF 密钥派生

```python
base = f"{pwd[:128]}|{t}|{mac}|{ip}|{temp}|{gold}|{cpu}|{gpu}"
       f"|{lat}|{lon}|{soviet_offset}|{trump_offset}"
       f"|QQ:{qq}|MAIL:{mail}"
       f"|FIX_VOL:{v0}|FIX_TS:{v1}|FIX_BIOS:{v2}"
       f"|FIX_SID:{v3}|FIX_CPU:{v4}|FIX_RAND:{rand}"
       f"|DEV_KEY:{dev_key}"
salt = f"{mac}|{ip}|{v0}|{v2}|{rand}"[:64]
seed = Argon2id(base, salt, t=2, m=32768, p=2)  # 16 bytes
```

- Argon2id 优先，fallback PBKDF2-SHA256 × 100000
- 硬件密钥模式 (`-hk`)：密码固定为 `____HK_MODE____`，实际密钥来自 `dev_key`（8192bit base62）
- 解密三阶段兼容：rv6 → rv5fake (rand=0) → legacy (rv5) → hk_legacy

---

## nbnn256 集成

nbnn256 作为可选封板层（`encrypt_mode`/`hk_encrypt`/`ecc_encrypt_mode` 中提示 "追加 nbnn256 可逆封板"）。

在 ECC 模式下，nbnn256 为**强制**环节（`_build_nbnn_output` 直接调用，不询问）。

加密前先 XOR(R1, 1024)，其中 R1 来自 `_gen_8192_store()`（每会话/每文件随机）。

---

## 8192bit 随机数对（R1 + R2）

| 组件 | 大小 | 保护方式 | 注册表键 |
|------|------|----------|----------|
| R1 | 1024 bytes | TPM (NCryptProtectSecret) | `Tpm8192R1R2` (R1+R2 拼接) |
| R2 | 1024 bytes | DPAPI (CryptProtectData) | `Tpm8192R2` |

- R1 用于 XOR 加密前数据（`encrypt_flow` 输出）
- R2 保留供扩展使用
- 每次 `_gen_8192_store()` 调用重新生成

---

## ECC (secp256k1 ECIES)

### 密钥生成

```python
ec.generate_private_key(ec.SECP256K1())
```

- 私钥 DER/PKCS8 → TPM 密封 → `HKCU\...\EcKey`
- 公钥 PEM 输出到文件

### 加密（ECIES 包装）

```python
# 发送方：
ephem = ec.generate_private_key(ec.SECP256K1())
shared = ECDH(ephem, recipient_pub)
dk = HKDF-SHA256(shared) → 32 bytes
nonce = random 12 bytes
ct = AES-256-GCM(dk, nonce, data)
output = DER(ephem_pub) + nonce + ct
```

### 解密

```python
# 接收方（私钥 TPM 解封）：
ephem_pub = DER(ephem_der)
shared = ECDH(priv, ephem_pub)
dk = HKDF-SHA256(shared) → 32 bytes
data = AES-256-GCM(dk, nonce, ct)
```

### 文件格式

```
=== ECC ENCRYPTED ===
【ECC密钥】
<base64 ECIES 包, 每行 76 字符>
=== NBNN256 v2 ===
【密文】
<cd base64>
---NBNN-INFO---
Z:<hex>
enc_time:<ts>
ipv4:<ip>
ipv6:<ipv6>
hm:<hm>
n_orig_len:<len>
u_len:<len>
IFON=<nbnn256 加密 meta (LZMA2 + base64)>
============
```

---

## 兼容性

- **Windows only** (winreg, TPM via ncrypt.dll, DPAPI via crypt32.dll)
- Python ≥ 3.12 (requires `sys.set_int_max_str_digits(0)` for nbnn256 large ints)
- 依赖：`argon2-cffi`（可选，fallback PBKDF2）、`cryptography`（ECC 模式）

### 旧版兼容

- 解密三层 seed 回溯：rv6 → rv5fake → legacy → hk_legacy
- 旧 char 模式 12 层解码器（`_old_dec_*`）：hex/bin/dec/oct/unicode/html/punycode 等
- nbnn256 v1/v2 双格式检测

---

## 安全特性

1. **硬件绑定**：6 值注册表指纹 + 8192bit 设备密钥，仅本机可用
2. **多保护层**：DPAPI（用户态）+ TPM/NCrypt（芯片级）+ XOR 密封
3. **可逆封板**：nbnn256 保护元数据，密钥 3044 bit 熵
4. **每会话随机**：8192bit R1+R2 每次加密重新生成
5. **ECIES 前向安全**：ephemeral key 每次不同
6. **干扰机制**：解密失败返回 `[干扰]<hash>` 伪输出
7. **密码缓存**：最后密码 TPM 密封至 `PwdBox`
