# XXTEA 加密算法的 D 实现

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

[![Build Status](https://travis-ci.org/xxtea/xxtea-d.svg?branch=master)](https://travis-ci.org/xxtea/xxtea-d)
[![DUB](https://img.shields.io/dub/v/xxtea.svg)](http://code.dlang.org/packages/xxtea)
[![DUB](https://img.shields.io/dub/l/xxtea.svg)](http://code.dlang.org/packages/xxtea)
[![DUB](https://img.shields.io/dub/dt/xxtea.svg)](http://code.dlang.org/packages/xxtea)
[![DUB](https://img.shields.io/dub/dm/xxtea.svg)](http://code.dlang.org/packages/xxtea)
[![DUB](https://img.shields.io/dub/dw/xxtea.svg)](http://code.dlang.org/packages/xxtea)
[![DUB](https://img.shields.io/dub/dd/xxtea.svg)](http://code.dlang.org/packages/xxtea)

## 简介

XXTEA 是一个快速安全的加密算法。本项目是 XXTEA 加密算法的 D 实现。

它不同于原始的 XXTEA 加密算法。它是针对原始二进制数据类型进行加密的，而不是针对 32 位 int 数组。同样，密钥也是原始二进制数据类型。

## 使用

这是一个 dub 库（http://code.dlang.org/about）。只需要在你的 package.json 文件中添加以下依赖即可：

```json
{
    ...
    "dependencies": {
        "xxtea": "~>1.0.0",
        ...
    }
}
```

app.d 示例代码：

```d
import xxtea;
import std.stdio;

void main() {
    auto text = "Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encryptToBase64(text, key);
    writeln(encrypt_data);
    auto decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    assert(text == decrypt_data);
}
```
