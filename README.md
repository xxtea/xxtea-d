# XXTEA for D

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for D.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts raw binary data instead of 32bit integer array, and the key is also the raw binary data.

## Usage

This is a dub library (http://code.dlang.org/about). Just add dependancy to your package.json:

```json
{
    ...
    "dependencies": {
        "xxtea": "~>1.0.0",
        ...
    }
}
```

A simple source code example is in the provided app.d and looks like this:

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
