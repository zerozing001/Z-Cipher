# Z 密码（OMNI Cipher / Z–QCTv6）教学模拟实现

> ⚠️ **使用前必读**：[DISCLAIMER.md](DISCLAIMER.md)（免责声明）· [RISKS.md](RISKS.md)（风险说明与不适用场景）
>
> 本项目是**密码学教学模拟**，不是真实安全加密系统，**不得用于实际保密通信**。
>
> English overview: [README.en.md](README.en.md)

自然语言 ⇄ Z 密码的双向翻译程序，按 `SPEC.md` 中的 **Z 密码 v1 教学模拟规范**实现。
纯标准库，无第三方依赖。

---

## ⚠️ 安全声明

> **本程序是 Z密码教学模拟实现，不是经过密码学审查的真实安全加密系统，不得用于实际保密通信。
> Z密码的安全性声明属于协议设计演练，不构成安全保证。**

补充说明：

- 二度加密层是 **HMAC-SHA256 构造的 CTR + encrypt-then-MAC 教学替代方案**，不等同于 AES-256-GCM 等经审查的 AEAD。
- 本实现**未**通过 NIST/Diehard 等随机性检验，"统计不可区分"只是协议设计层面的描述。
- 门限、哈希链、令牌等机制只在本代码内部自洽，**未**经过独立密码学审计。
- 不得声称本程序"不可破解""绝对安全"。

---

## 目录结构

```
z-cipher/
├── SPEC.md                 Z 密码 v1 教学模拟规范
├── README.md               本文件
├── zcipher/
│   ├── __init__.py         包导出
│   ├── spec.py             固定参数、域分离标签、4 张字符集表
│   ├── errors.py           错误码与异常
│   ├── prng.py             确定性字节流（HMAC-SHA256 计数器模式）
│   ├── kdf.py              HKDF、子密钥派生、GF(256) Shamir 门限
│   ├── layers.py           符号编码 / 分形掩码 / 混沌混合 / PKCS#7 填充
│   ├── aead.py             二度加密（CTR + HMAC）
│   ├── split.py            三次拆分、随机配对、真假块混排
│   ├── vmcode.py           虚拟机式指令编码与解释
│   ├── charset.py          多语言字符集编码
│   ├── token.py            哈希链与过滤令牌
│   └── api.py              encode / decode / 失败状态机
├── examples/
│   └── demo.py             双向翻译示例
└── tests/
    └── test_zcipher.py     20 项验收测试
```

## 环境要求

- Python **3.10+**（使用了 `from __future__ import annotations` 与 `X | None` 写法）
- 无第三方依赖

## 快速开始

```python
from zcipher import encode, decode, make_key_material

km = make_key_material(threshold=3, n=5, seed=b"demo-seed")

env = encode("中文 English 123 混合文本", km, seed=b"dynamic-001")
print(env[:120])
print(decode(env, km))          # 还原明文
```

运行示例：

```bash
cd z-cipher
python -X utf8 examples/demo.py
```

输出：

```
[明文] Z密码 v1 教学模拟：Hello, 世界！123
[封装长度] 1293
[封装片段] ZPWD1.eyJuIjo1LCJxIjoi...
[还原] Z密码 v1 教学模拟：Hello, 世界！123
[可逆] True
[换 seed 后封装不同] True
[同 seed 可复现] True
```

## 实时双向翻译

逐行即时翻译，自动识别方向：以 ZPWD1. 开头按解密处理，其余按加密处理。

    cd z-cipher
    python -m zcipher.live --key 你的口令

    Z 密码 v1 实时双向翻译（教学模拟，非真实加密）
      zcipher> 你好，实时翻译！
      ZPWD1.eyJoIjoi...（完整封装）
      zcipher> ZPWD1.eyJoIjoi...（粘贴回去）
      你好，实时翻译！

非交互用法：

    python -m zcipher.live --key demo --text 你好
    cmd /c "python -m zcipher.live --key demo --stdin < input.txt"
    python -m zcipher.live --key demo --seed s1 --text 你好

参数：

| 参数 | 说明 |
|------|------|
| --key | 口令，用于派生教学用暗码分量；也可用环境变量 ZCIPHER_KEY |
| --threshold / --copies | 门限 / 副本数，默认 3 / 5 |
| --seed | 固定动态种子，便于复现 |
| --text | 非交互：翻译一行后退出 |
| --stdin | 逐行读取标准输入 |
| --pseudo | 启用失败状态机（首次伪响应、再次锁定），默认 strict |

> 实时模式默认使用 strict，避免交互过程中被锁定；需要演示失败状态机时加 --pseudo。

## 接口

| 接口 | 说明 |
|------|------|
| `encode(text, key_material, seed=None) -> str` | 自然语言 → 密文封装。`seed` 相同则输出完全一致；`seed=None` 时用系统随机数 |
| `decode(envelope, key_material, fail_mode="pseudo") -> str` | 密文封装 → 自然语言 |
| `make_key_material(threshold=3, n=5, length=32, seed=b"...")` | 生成一整套暗码分量（5 份，任意 3 份可重建） |
| `KeyMaterial(components, threshold, n=None, rules=...)` | 用自定义分量构造密钥材料 |
| `reset_state()` | 清空失败状态机（测试用） |

异常均继承 `ZCipherError` 并携带稳定 `code`：

```python
from zcipher import ZCipherError, E_TAMPER

try:
    decode(bad_envelope, km, fail_mode="strict")
except ZCipherError as exc:
    print(exc.code)     # 如 E_HASH / E_TAMPER / E_TOKEN / E_THRESHOLD ...
```

`fail_mode` 两种取值：

- `"pseudo"`（默认）：第 1 次失败抛 `PseudoResponse`（`code=E_PSEUDO`，`cause` 是真实原因，附带 16 字符伪明文）；
  第 2 次失败锁定该 `sid` 并抛 `E_LOCKED`。
- `"strict"`：直接抛原始错误码，不进入状态机。

## 错误码

| 码 | 含义 |
|----|------|
| `E_HEADER` | 协议头/版本不匹配 |
| `E_FORMAT` | 封装结构或参数区非法 |
| `E_THRESHOLD` | 副本数或暗码分量不足 |
| `E_TOKEN` | 过滤令牌校验失败 |
| `E_HASH` | 哈希链断裂或链尾锚点不匹配 |
| `E_TAMPER` | 二度加密认证标签失败 |
| `E_DECODE` | 字符集/指令流/填充/UTF-8 解码失败 |
| `E_LOCKED` | 该密文会话已锁定 |
| `E_INPUT` | 入参类型或长度非法 |
| `E_PSEUDO` | 首次失败的伪响应 |

## 测试

```bash
cd z-cipher
python -X utf8 -m unittest discover -s tests -v
```

预期结果（实测）：

```
Ran 20 tests in 0.113s

OK
```

覆盖项：

1. 中/英/数字/标点混合文本双向可逆（含空文本）
2. 相同文本 + 相同 seed 输出相同
3. 相同文本 + 不同 seed 输出不同
4. 篡改任意码片 → `E_HASH`（链校验）/ `E_TAMPER`
5. 门限副本不足 → `E_THRESHOLD`
6. 暗码分量不足 → `E_THRESHOLD`
7. 错误过滤令牌 → `E_TOKEN`
8. 非法协议头 → `E_HEADER`
9. 首次失败伪响应 → 再次失败 `E_LOCKED`
10. 码片重排 → `E_FORMAT` / `E_HASH`
11. 任意 3 份暗码分量子集均可解密
12. 非法入参（`bytes` 明文、超长文本、错误 `key_material`）→ `E_INPUT`

## 已知限制

- 不实现网络传输、硬件根信任、物理防篡改等现实层内容。
- 失败状态机是**进程内存**状态，进程重启后清零；不跨进程共享。
- 未做常量时间实现的整体保证：认证标签比较使用 `hmac.compare_digest`，其余分支未做时序硬化。
- 大文本（接近 65536 字节上限）时，分形掩码按位迭代，编码耗时约秒级。
- 字符集编码为公开映射，"密文看起来像自然语言"只是外观，不构成任何混淆意义上的安全性。
- 未实现 CLI；如需命令行入口见 `SPEC.md` 第 10 节 P6。

## 参考

- 规范细节：`SPEC.md`
- 双向示例：`examples/demo.py`
- 验收测试：`tests/test_zcipher.py`
