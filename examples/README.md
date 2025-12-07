# SM-GO-BC Examples

本目录包含 SM-GO-BC 库的完整使用示例。所有示例都可以直接运行。

## 📚 示例列表

### SM3 哈希算法

| 文件 | 说明 | 演示内容 |
|------|------|---------|
| [sm3_demo.go](./sm3_demo.go) | SM3 哈希示例 | 基本哈希、分段更新、空数据处理、性能测试 |

**运行示例**:
```bash
go run sm3_demo.go
```

---

### SM2 公钥密码算法

| 文件 | 说明 | 演示内容 |
|------|------|---------|
| [sm2_demo.go](./sm2_demo.go) | SM2 密钥对生成 | 生成密钥对、查看公私钥、密钥格式 |
| [sm2_sign_demo.go](./sm2_sign_demo.go) | SM2 数字签名 | 签名生成、签名验证、错误验证 |
| [sm2_encryption_demo.go](./sm2_encryption_demo.go) | SM2 公钥加密 | 加密、解密、不同长度消息、C1C2C3 模式 |
| [sm2_key_exchange_example.go](./sm2_key_exchange_example.go) | SM2 密钥交换 | ECDH 协议、双方密钥协商、共享密钥验证 |

**运行示例**:
```bash
go run sm2_demo.go                    # 密钥对生成
go run sm2_sign_demo.go               # 数字签名
go run sm2_encryption_demo.go         # 公钥加密
go run sm2_key_exchange_example.go    # 密钥交换
```

---

### SM4 分组密码算法

| 文件 | 说明 | 演示内容 |
|------|------|---------|
| [sm4_demo.go](./sm4_demo.go) | SM4 基础示例 | 基本加密解密操作 |
| [sm4_cbc_demo.go](./sm4_cbc_demo.go) | SM4 CBC 模式 | CBC 加密、PKCS7 填充、错误处理 |
| [sm4_ctr_demo.go](./sm4_ctr_demo.go) | SM4 CTR 模式 | 计数器模式、流式加密、并行化 |
| [sm4_cfb_demo.go](./sm4_cfb_demo.go) | SM4 CFB 模式 | 密文反馈、CFB8/CFB64/CFB128 配置 |
| [sm4_ecb_demo.go](./sm4_ecb_demo.go) | SM4 ECB 模式 | 电子密码本、模式泄露演示（教育用途） |
| [sm4_modes_comparison.go](./sm4_modes_comparison.go) | SM4 多模式对比 | ECB/CBC/CTR/OFB/CFB/GCM 性能和特性对比 |

**运行示例**:
```bash
go run sm4_demo.go                    # 基础示例
go run sm4_cbc_demo.go                # CBC 模式
go run sm4_ctr_demo.go                # CTR 模式
go run sm4_cfb_demo.go                # CFB 模式
go run sm4_ecb_demo.go                # ECB 模式（仅教育用途）
go run sm4_modes_comparison.go        # 多模式对比
```

---

## 🚀 快速开始

### 前置条件

- Go >= 1.21
- 安装 sm-go-bc 库

```bash
go get github.com/lihongjie0209/sm-go-bc
```

### 运行所有示例

```bash
# 进入示例目录
cd examples

# 运行单个示例
go run sm3_demo.go

# 或者批量运行
for file in *.go; do
    echo "Running $file..."
    go run "$file"
    echo "---"
done
```

---

## 📝 示例说明

### SM3 示例

#### 基本哈希
```go
digest := digests.NewSM3Digest()
data := []byte("Hello, SM3!")
digest.Update(data, 0, len(data))

hash := make([]byte, 32)
digest.DoFinal(hash, 0)
fmt.Printf("Hash: %x\n", hash)
```

#### 分段更新
```go
digest := digests.NewSM3Digest()
digest.Update([]byte("Hello, "), 0, 7)
digest.Update([]byte("World!"), 0, 6)

hash := make([]byte, 32)
digest.DoFinal(hash, 0)
```

---

### SM2 示例

#### 密钥对生成
```go
curve := ec.SM2P256V1()
privateKey, _ := rand.Int(rand.Reader, curve.N)
publicKey := curve.G.Multiply(privateKey)
```

#### 数字签名
```go
signer := signers.NewSM2Signer()
signer.Init(true, privateKeyParams)
signature, _ := signer.GenerateSignature(message)

signer.Init(false, publicKeyParams)
isValid := signer.VerifySignature(message, signature)
```

#### 公钥加密
```go
engine := engines.NewSM2Engine()
engine.Init(true, publicKeyParams)
ciphertext, _ := engine.ProcessBlock(plaintext, 0, len(plaintext))

engine.Init(false, privateKeyParams)
decrypted, _ := engine.ProcessBlock(ciphertext, 0, len(ciphertext))
```

---

### SM4 示例

#### CBC 模式（推荐）
```go
engine := engines.NewSM4Engine()
cbc := modes.NewCBCBlockCipher(engine)

keyParam := params.NewKeyParameter(key)
ivParam := params.NewParametersWithIV(keyParam, iv)
cbc.Init(true, ivParam)

// 加密（需要先填充数据到16字节的倍数）
cbc.ProcessBlock(plaintext, 0, ciphertext, 0)
```

#### CTR 模式（流式加密）
```go
engine := engines.NewSM4Engine()
ctr := modes.NewCTRBlockCipher(engine)

keyParam := params.NewKeyParameter(key)
ivParam := params.NewParametersWithIV(keyParam, iv)
ctr.Init(true, ivParam)

// CTR 模式无需填充
ctr.ProcessBlock(plaintext, 0, ciphertext, 0)
```

#### GCM 模式（AEAD）
```go
engine := engines.NewSM4Engine()
gcm := modes.NewGCMBlockCipher(engine)

keyParam := params.NewKeyParameter(key)
aeadParam := params.NewAEADParameters(keyParam, 128, nonce, aad)
gcm.Init(true, aeadParam)

// 加密并生成认证标签
processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
finalLen, _ := gcm.DoFinal(ciphertext, processed)
```

---

## ⚠️ 安全注意事项

### ECB 模式警告
- ❌ **不要在生产环境使用 ECB 模式**
- ECB 模式会泄露数据模式，不安全
- `sm4_ecb_demo.go` 仅用于教育目的

### 推荐的加密模式
1. **GCM** - 认证加密（AEAD），最安全
2. **CTR** - 流式加密，可并行化
3. **CBC** - 传统模式，需要加 MAC
4. **CFB** - 流式加密变体

### IV/Nonce 要求
- ✅ 每次加密使用不同的 IV/Nonce
- ✅ IV 可以公开，但必须随机
- ✅ GCM 的 Nonce 推荐 12 字节
- ❌ 不要重用 IV/Nonce

### 密钥管理
- ✅ 使用安全的随机数生成器
- ✅ 密钥长度：SM4 = 16 字节
- ❌ 不要硬编码密钥
- ❌ 不要在代码中存储密钥

---

## 📊 性能对比

各种模式的相对性能（仅供参考）：

```
ECB:  ~45 MB/s  (最快，但不安全)
CBC:  ~40 MB/s  (传统模式)
CTR:  ~38 MB/s  (推荐)
OFB:  ~36 MB/s  (流式)
CFB:  ~35 MB/s  (流式)
GCM:  ~18 MB/s  (AEAD，最安全)
```

---

## 🎓 学习路径

### 新手入门
1. 从 SM3 哈希开始 (`sm3_demo.go`)
2. 学习 SM4 对称加密 (`sm4_cbc_demo.go`)
3. 了解 SM2 签名 (`sm2_sign_demo.go`)

### 进阶学习
1. 探索不同的 SM4 模式 (`sm4_modes_comparison.go`)
2. 学习 SM2 加密 (`sm2_encryption_demo.go`)
3. 理解密钥交换 (`sm2_key_exchange_example.go`)

### 高级应用
1. 研究 GCM AEAD 模式
2. 实现完整的加密通信方案
3. 性能优化和安全审计

---

## 📖 参考资料

### 国密算法标准
- **SM2**: GM/T 0003-2012 (椭圆曲线公钥密码算法)
- **SM3**: GM/T 0004-2012 (密码杂凑算法)
- **SM4**: GB/T 32907-2016 (分组密码算法)

### 相关链接
- [主 README](../README.md) - 项目概览
- [API 文档](../docs/API.md) - 完整 API 参考
- [实现状态](../docs/PROGRESS.md) - 开发进度

---

## 💡 常见问题

### Q: 如何选择加密模式？

**A**: 根据需求选择：
- **最安全**: GCM (认证加密)
- **最快**: CTR (流式，可并行)
- **传统**: CBC (需要加 MAC)
- **流式**: CFB/OFB
- **永远不要**: ECB (不安全)

### Q: 加密后数据长度会变化吗？

**A**: 取决于模式：
- **ECB/CBC**: 需要填充，长度会增加到 16 字节的倍数
- **CTR/CFB/OFB**: 流式模式，长度不变
- **GCM**: 长度 + 认证标签（通常 16 字节）

### Q: IV 和 Nonce 有什么区别？

**A**: 
- **IV** (Initialization Vector): CBC/CTR/CFB/OFB 使用，16 字节
- **Nonce** (Number used Once): GCM 使用，推荐 12 字节
- 都必须每次加密时不同，但可以公开

### Q: 如何处理填充？

**A**: 
```go
// 使用 PKCS7 填充
padding := paddings.NewPKCS7Padding()
paddedCipher := modes.NewPaddedBufferedBlockCipher(cbc, padding)

// 或者使用不需要填充的模式（CTR/CFB/OFB/GCM）
```

---

## 🤝 贡献

发现示例有问题或有改进建议？欢迎：
1. 提出 [Issue](../../issues)
2. 提交 [Pull Request](../../pulls)
3. 添加新的示例

---

**示例持续更新中，欢迎反馈！** 🚀
