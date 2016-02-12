/**********************************************************\
 *                                                        *
 * xxtea.d                                                *
 *                                                        *
 * hprose bytes io library for D.                         *
 *                                                        *
 * LastModified: Feb 13, 2016                             *
 * Author: Ma Bingyao <andot@hprose.com>                  *
 *                                                        *
\**********************************************************/

module xxtea;

@safe:

import std.base64;
import std.utf;
import std.traits;

static class XXTEA {
private:
    enum DELTA = 0x9e3779b9;
    pure static uint mx(uint sum, uint y, uint z, ulong p, uint e, uint[] k) {
        return (z >> 5 ^ y << 2) + (y >> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
    }
    pure static uint[] encrypt(uint[] v, uint[] k) {
        if (v.length < 2) return v;
        ulong n = v.length - 1, p;
        uint z = v[n], y, sum = 0u, e;
        int q = 6 + 52 / (n + 1);
        while (0 < q--) {
            sum += DELTA;
            e = sum >> 2 & 3;
            for (p = 0; p < n; p++) {
                y = v[p + 1];
                z = v[p] += mx(sum, y, z, p, e, k);
            }
            y = v[0];
            z = v[n] += mx(sum, y, z, p, e, k);
        }
        return v;
    }
    pure static uint[] decrypt(uint[] v, uint[] k) {
        if (v.length < 2) return v;
        ulong n = v.length - 1, p;
        uint z, y = v[0], sum, e;
        int q = 6 + 52 / (n + 1);
        sum = q * DELTA;
        while (sum != 0) {
            e = sum >> 2 & 3;
            for (p = n; p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= mx(sum, y, z, p, e, k);
            }
            z = v[n];
            y = v[0] -= mx(sum, y, z, p, e, k);
            sum -= DELTA;
        }
        return v;
    }
    pure static const(ubyte[]) fixkey(in ubyte[] key) {
        if (key.length == 16) return key;
        if (key.length > 16) {
            return key[0..16];
        }
        else {
            ubyte[] fixedkey = key.dup();
            fixedkey.length = 16;
            return fixedkey;
        }
    }
    pure static uint[] touints(in ubyte[] data, bool includeLength) {
        ulong length = data.length;
        ulong n = (((length & 3) == 0) ? (length >> 2) : ((length >> 2) + 1));
        uint[] result;
        if (includeLength) {
            result = new uint[n + 1];
            result[n] = cast(uint)length;
        }
        else {
            result = new uint[n];
        }
        for (ulong i = 0; i < length; ++i) {
            result[i >> 2] |= cast(uint)data[i] << ((i & 3) << 3);
        }
        return result;
    }
    pure static ubyte[] tobytes(in uint[] data, bool includeLength) {
        ulong n = data.length << 2;
        if (includeLength) {
            ulong m = data[data.length - 1];
            n -= 4;
            if ((m < n - 3) || (m > n)) {
                return null;
            }
            n = m;
        }
        ubyte[] result = new ubyte[n];
        for (ulong i = 0; i < n; ++i) {
            result[i] = cast(ubyte)(data[i >> 2] >> ((i & 3) << 3));
        }
        return result;
    }
public:
    pure static ubyte[] encrypt(in ubyte[] data, in ubyte[] key) {
        if (data.length == 0) return null;
        return tobytes(encrypt(touints(data, true), touints(fixkey(key), false)), false);
    }
    pure static ubyte[] decrypt(in ubyte[] data, in ubyte[] key) {
        if (data.length == 0) return null;
        return tobytes(decrypt(touints(data, false), touints(fixkey(key), false)), true);
    }
    pure static ubyte[] encrypt(T, U)(in T data, in U key)
        if ((isSomeString!T || is(T == byte[]) || is(T == ubyte[])) &&
            (isSomeString!U || is(U == byte[]) || is(U == ubyte[]))) {
        static if (isSomeString!T && isSomeString!U) {
            return encrypt(cast(const(ubyte[]))toUTF8(data), cast(const(ubyte[]))toUTF8(key));
        }
        else static if (isSomeString!T && !isSomeString!U) {
            return encrypt(cast(const(ubyte[]))toUTF8(data), cast(const(ubyte[]))key);
        }
        else static if (!isSomeString!T && isSomeString!U) {
            return encrypt(cast(const(ubyte[]))data, cast(const(ubyte[]))toUTF8(key));
        }
        else {
            return encrypt(cast(const(ubyte[]))data, cast(const(ubyte[]))key);
        }
    }
    pure static ubyte[] decrypt(T)(in ubyte[] data, in T key)
    if (isSomeString!T || is(T == byte[])) {
        static if (isSomeString!T) {
            return decrypt(data, cast(const(ubyte[]))toUTF8(key));
        }
        else {
            return decrypt(data, cast(const(ubyte[]))key);
        }
    }
    pure static string encryptToBase64(T, U)(in T data, in U key) 
        if ((isSomeString!T || is(T == byte[]) || is(T == ubyte[])) &&
        (isSomeString!U || is(U == byte[]) || is(U == ubyte[]))) {
        return Base64.encode(encrypt(data, key));
    }
    pure static ubyte[] decryptFromBase64(T)(in string data, in T key)
    if (isSomeString!T || is(T == byte[]) || is(T == ubyte[])) {
        return decrypt(Base64.decode(data), key);
    }
}

unittest {
    enum text = "Hello World! 你好，中国！";
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encryptToBase64(text, key);
    enum decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    static assert(text == decrypt_data);
}

unittest {
    enum text = "Hello World! 你好，中国！";
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encrypt(text, key);
    enum decrypt_data = XXTEA.decrypt(encrypt_data, key);
    static assert(text == decrypt_data);
}


unittest {
    import std.conv;
    enum text = to!(wchar[])("Hello World! 你好，中国！");
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encryptToBase64(text, key);
    enum decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    import std.conv;
    enum text = to!(wchar[])("Hello World! 你好，中国！");
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encrypt(text, key);
    enum decrypt_data = XXTEA.decrypt(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    enum text = cast(wstring)"Hello World! 你好，中国！";
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encryptToBase64(text, key);
    enum decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    enum text = cast(wstring)"Hello World! 你好，中国！";
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encrypt(text, key);
    enum decrypt_data = XXTEA.decrypt(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    import std.conv;
    enum text = to!(dchar[])("Hello World! 你好，中国！");
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encryptToBase64(text, key);
    enum decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    import std.conv;
    enum text = to!(dchar[])("Hello World! 你好，中国！");
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encrypt(text, key);
    enum decrypt_data = XXTEA.decrypt(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    enum text = cast(dstring)"Hello World! 你好，中国！";
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encryptToBase64(text, key);
    enum decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    enum text = cast(dstring)"Hello World! 你好，中国！";
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encrypt(text, key);
    enum decrypt_data = XXTEA.decrypt(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    auto text = "Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encryptToBase64(text, key);
    auto decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    assert(text == decrypt_data);
}

unittest {
    auto text = "Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encrypt(text, key);
    auto decrypt_data = XXTEA.decrypt(encrypt_data, key);
    assert(text == decrypt_data);
}

unittest {
    import std.conv;
    auto text = to!(wchar[])("Hello World! 你好，中国！");
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encryptToBase64(text, key);
    auto decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}

unittest {
    import std.conv;
    auto text = to!(wchar[])("Hello World! 你好，中国！");
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encrypt(text, key);
    auto decrypt_data = XXTEA.decrypt(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}

unittest {
    auto text = cast(wstring)"Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encryptToBase64(text, key);
    auto decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}

unittest {
    auto text = cast(wstring)"Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encrypt(text, key);
    auto decrypt_data = XXTEA.decrypt(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}

unittest {
    import std.conv;
    auto text = to!(dchar[])("Hello World! 你好，中国！");
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encryptToBase64(text, key);
    auto decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}

unittest {
    import std.conv;
    enum text = to!(dchar[])("Hello World! 你好，中国！");
    enum key = "1234567890";
    enum encrypt_data = XXTEA.encrypt(text, key);
    enum decrypt_data = XXTEA.decrypt(encrypt_data, key);
    static assert(toUTF8(text) == decrypt_data);
}

unittest {
    auto text = cast(dstring)"Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encryptToBase64(text, key);
    auto decrypt_data = XXTEA.decryptFromBase64(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}

unittest {
    auto text = cast(dstring)"Hello World! 你好，中国！";
    auto key = "1234567890";
    auto encrypt_data = XXTEA.encrypt(text, key);
    auto decrypt_data = XXTEA.decrypt(encrypt_data, key);
    assert(toUTF8(text) == decrypt_data);
}
