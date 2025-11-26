from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def decrypt_with_key(encrypted_data, hex_key):
    """
    用十六进制密钥解密
    """
    # 将十六进制密钥转换为字节
    key = binascii.unhexlify(hex_key)
    
    # 创建AES解密器 (ECB模式)
    cipher = AES.new(key, AES.MODE_ECB)
    
    # 解密
    decrypted = cipher.decrypt(encrypted_data)
    
    # 尝试移除PKCS7填充
    try:
        decrypted = unpad(decrypted, AES.block_size)
        print("✅ 解密成功 (PKCS7填充)")
    except:
        print("⚠️  解密数据但填充可能不正确")
    
    return decrypted

# 测试密钥
test_keys = [
    "6ED592596D456246F1E8E629BCB7F52B",  # 最有可能
    "5516c21c9faee61b3d5af409328a33dc",
    "af96400eec00bcb9bc4f9524e29a0f47", 
    "ce3914ae6cb2468997fa4ddbeabd5879"
]

# 读取你的加密数据文件
with open("encrypted_game_data.bin", "rb") as f:
    encrypted_data = f.read()

print(f"加密数据长度: {len(encrypted_data)} 字节")

for key in test_keys:
    print(f"\n🔑 测试密钥: {key}")
    try:
        decrypted = decrypt_with_key(encrypted_data, key)
        
        # 检查解密结果
        if len(decrypted) > 0:
            print(f"解密后长度: {len(decrypted)} 字节")
            
            # 检查是否是文本
            try:
                text = decrypted.decode('utf-8')
                print(f"文本内容: {text[:100]}...")
            except:
                print("非UTF-8文本，可能是二进制数据")
                
            # 保存解密结果
            with open(f"decrypted_with_{key[:8]}.bin", "wb") as f:
                f.write(decrypted)
    except Exception as e:
        print(f"❌ 解密失败: {e}")