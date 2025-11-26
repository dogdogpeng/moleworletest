#!/usr/bin/env python3
import os, sys, hashlib, struct, zlib
from Crypto.Cipher import AES

KEY = bytes.fromhex('396535433fa0d99aa04c88bfe7d725d04'[:32])
IV  = b'\0' * 16
FILE_DAT = 'userinfo.dat'
FILE_BIN = 'userinfo.bin'

# ---------- 工具 ----------
def die(msg): print(msg); sys.exit(1)
def read_dat(): return open(FILE_DAT, 'rb').read()
def write_dat(data): open(FILE_DAT, 'wb').write(data)

# ---------- 解密 ----------
def decrypt():
    blob = read_dat()
    if len(blob) < 16: die('文件太短')
    md5_file, cipher = blob[-16:], blob[:-16]
    orig_len = struct.unpack('<I', cipher[4:8])[0]
    cipher = cipher[:orig_len]
    cipher = cipher[:len(cipher) & ~0xF]
    plain  = AES.new(KEY, AES.MODE_CBC, IV).decrypt(cipher)
    if hashlib.md5(cipher).digest() != md5_file:
        print('⚠️  MD5 不匹配，继续但可能无效')
    open(FILE_BIN, 'wb').write(plain)
    print(f'✅ 解密完成 -> {FILE_BIN}')

# ---------- 加密 ----------
def encrypt():
    plain = open(FILE_BIN, 'rb').read()
    pad = 16 - (len(plain) % 16)
    plain += bytes([pad]) * pad
    cipher = AES.new(KEY, AES.MODE_CBC, IV).encrypt(plain)

    # 1. 修正长度字段
    header  = cipher[:4]
    new_len = struct.pack('<I', len(cipher))
    cipher  = header + new_len + cipher[8:]

    # 2. 修正明文 CRC32（偏移 0x08~0x0B）
    crc = zlib.crc32(plain) & 0xFFFFFFFF
    cipher = cipher[:8] + struct.pack('<I', crc) + cipher[12:]

    # 3. MD5 只算密文部分
    md5 = hashlib.md5(cipher).digest()
    write_dat(cipher + md5)
    print(f'✅ 加密完成 -> {FILE_DAT}')

# ---------- 改名字 ----------
def change_name(new_name):
    decrypt()
    data = bytearray(open(FILE_BIN, 'rb').read())
    # 名字字段举例：0x10 起 16 字节
    name_b = new_name.encode('utf-8')[:16].ljust(16, b'\0')
    data[0x10:0x20] = name_b
    open(FILE_BIN, 'wb').write(data)
    encrypt()
    print(f'✅ 名字已改为：{new_name}')

# ---------- 入口 ----------
if __name__ == '__main__':
    if len(sys.argv) < 2: die('用法: dec / enc / name "新名字"')
    cmd = sys.argv[1]
    if cmd == 'dec': decrypt()
    elif cmd == 'enc': encrypt()
    elif cmd == 'name' and len(sys.argv) == 3: change_name(sys.argv[2])
    else: die('参数错误')
