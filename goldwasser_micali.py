import random
import math


class GoldwasserMicali:
    """
    Goldwasser-Micali密码体制实现

    公钥pk = (n, z)，其中n = p×q，z是模n的二次非剩余且雅可比符号(z|n) = +1
    私钥sk = (p, q)，其中p和q是满足p ≡ 3 mod 4和q ≡ 3 mod 4的质数
    """

    def __init__(self, key_size=16):
        """
        初始化Goldwasser-Micali密码体制

        参数:
            key_size (int): 密钥大小（比特），决定了质数p和q的大小
        """
        self.key_size = key_size
        self.public_key = None  # (n, z)
        self.private_key = None  # (p, q)

    def is_prime(self, n, k=5):
        """
        Miller-Rabin素性测试

        参数:
            n (int): 待测试的数
            k (int): 测试轮数，轮数越多准确率越高

        返回:
            bool: 如果n很可能是质数则返回True，否则返回False
        """
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False

        # 写成n-1 = d*2^s
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        # 进行k轮测试
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_large_prime_3mod4(self, bit_length):
        """
        生成指定比特长度且满足p ≡ 3 mod 4的大质数

        参数:
            bit_length (int): 质数的比特长度

        返回:
            int: 生成的大质数p，满足p ≡ 3 mod 4
        """
        while True:
            # 生成一个随机的bit_length位整数
            num = random.getrandbits(bit_length)
            # 确保是奇数
            num |= 1
            # 确保num ≡ 3 mod 4
            if num % 4 != 3:
                num += (3 - num % 4)
                # 如果加完后位数超过了，重新生成
                if num.bit_length() > bit_length:
                    continue
            # 检查是否是质数
            if self.is_prime(num):
                return num

    def legendre_symbol(self, a, p):
        """
        计算勒让德符号 (a|p)

        参数:
            a (int): 整数
            p (int): 奇质数

        返回:
            int: 勒让德符号值，-1, 0, 或 1
        """
        if a % p == 0:
            return 0
        result = pow(a, (p - 1) // 2, p)
        return -1 if result == p - 1 else result

    def jacobi_symbol(self, a, n):
        """
        计算雅可比符号 (a|n)

        参数:
            a (int): 整数
            n (int): 正奇数

        返回:
            int: 雅可比符号值，-1, 0, 或 1
        """
        if n <= 0 or n % 2 == 0:
            raise ValueError("n必须是正奇数")

        # 简化a mod n
        a = a % n
        result = 1

        while a != 0:
            # 消除a中的所有因子2
            while a % 2 == 0:
                a //= 2
                # 根据雅可比符号的性质：(2|n) = (-1)^((n^2-1)/8)
                if n % 8 == 3 or n % 8 == 5:
                    result = -result

            # 交换a和n
            a, n = n, a

            # 根据雅可比符号的互反律
            if a % 4 == 3 and n % 4 == 3:
                result = -result

            a = a % n

        return result if n == 1 else 0

    def generate_keys(self):
        """
        生成公钥和私钥

        公钥pk = (n, z)，其中：
            n = p×q
            z是模n的二次非剩余，且雅可比符号(z|n) = +1

        私钥sk = (p, q)，其中：
            p和q是满足p ≡ 3 mod 4和q ≡ 3 mod 4的质数

        返回:
            tuple: (public_key, private_key)
                public_key: (n, z)
                private_key: (p, q)
        """
        # 生成两个满足p ≡ 3 mod 4和q ≡ 3 mod 4的大质数
        half_key_size = self.key_size // 2
        p = self.generate_large_prime_3mod4(half_key_size)
        q = self.generate_large_prime_3mod4(half_key_size)

        # 确保p != q
        while p == q:
            q = self.generate_large_prime_3mod4(half_key_size)

        n = p * q

        # 找到z，满足：
        # 1. z是模n的二次非剩余
        # 2. 雅可比符号(z|n) = +1
        # 这样的z可以通过选择模p的非剩余和模q的非剩余来构造
        # 因为雅可比符号(z|n) = (z|p)*(z|q) = (-1)*(-1) = +1

        # 选择z_p是模p的非剩余
        z_p = 2
        while self.legendre_symbol(z_p, p) != -1:
            z_p += 1

        # 选择z_q是模q的非剩余
        z_q = 2
        while self.legendre_symbol(z_q, q) != -1:
            z_q += 1

        # 使用中国剩余定理找到z，使得z ≡ z_p mod p且z ≡ z_q mod q
        # z = z_p + k*p
        # z ≡ z_q mod q => z_p + k*p ≡ z_q mod q => k*p ≡ (z_q - z_p) mod q
        # k ≡ (z_q - z_p) * p^{-1} mod q

        # 计算p在模q下的逆元
        p_inv_q = pow(p, -1, q)
        k = ((z_q - z_p) % q) * p_inv_q % q
        z = z_p + k * p

        # 验证z的性质
        assert self.legendre_symbol(z % p, p) == -1, "z应该是模p的非剩余"
        assert self.legendre_symbol(z % q, q) == -1, "z应该是模q的非剩余"
        assert self.jacobi_symbol(z, n) == 1, "雅可比符号(z|n)应该是+1"

        self.public_key = (n, z)
        self.private_key = (p, q)

        return self.public_key, self.private_key

    def encrypt_bit(self, bit, public_key=None):
        """
        加密单个比特

        参数:
            bit (int): 待加密的比特，0或1
            public_key (tuple): (n, z)，如果为None则使用内部公钥

        返回:
            int: 加密后的密文
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("公钥未生成，请先调用generate_keys()")
            public_key = self.public_key

        n, z = public_key

        # 选择随机数r，满足gcd(r, n) = 1
        while True:
            r = random.randint(1, n - 1)
            if math.gcd(r, n) == 1:
                break

        # 计算密文
        if bit == 0:
            c = pow(r, 2, n)
        elif bit == 1:
            c = (pow(r, 2, n) * z) % n
        else:
            raise ValueError("比特必须是0或1")

        return c

    def encrypt(self, message, public_key=None):
        """
        加密消息（将消息转换为二进制后逐比特加密）

        参数:
            message (int or str or bytes): 待加密的消息
                如果是int: 直接转换为二进制
                如果是str: 先转换为bytes，再转换为二进制
                如果是bytes: 直接转换为二进制
            public_key (tuple): (n, z)，如果为None则使用内部公钥

        返回:
            list: 加密后的密文列表，每个元素对应一个加密的比特
        """
        # 处理不同类型的消息
        if isinstance(message, int):
            # 对于整数，转换为二进制字符串，去掉'0b'前缀
            binary_str = bin(message)[2:]
        elif isinstance(message, str):
            # 对于字符串，先转换为bytes，再转换为二进制
            binary_str = ''.join(format(byte, '08b') for byte in message.encode('utf-8'))
        elif isinstance(message, bytes):
            # 对于bytes，直接转换为二进制
            binary_str = ''.join(format(byte, '08b') for byte in message)
        else:
            raise TypeError("不支持的消息类型")

        # 逐比特加密
        ciphertext = []
        for bit_char in binary_str:
            bit = int(bit_char)
            c = self.encrypt_bit(bit, public_key)
            ciphertext.append(c)

        return ciphertext

    def decrypt_bit(self, c, private_key=None):
        """
        解密密文比特

        参数:
            c (int): 密文
            private_key (tuple): (p, q)，如果为None则使用内部私钥

        返回:
            int: 解密后的比特，0或1
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("私钥未生成，请先调用generate_keys()")
            private_key = self.private_key

        p, q = private_key

        # 计算勒让德符号
        ls_p = self.legendre_symbol(c % p, p)
        ls_q = self.legendre_symbol(c % q, q)

        # 判断是否为二次剩余
        if ls_p == 1 and ls_q == 1:
            return 0
        else:
            return 1

    def decrypt(self, ciphertext, private_key=None, output_type='int'):
        """
        解密整个密文

        参数:
            ciphertext (list): 密文列表
            private_key (tuple): (p, q)，如果为None则使用内部私钥
            output_type (str): 输出类型，'int', 'str', 或 'bytes'

        返回:
            int or str or bytes: 解密后的消息
        """
        # 逐比特解密
        binary_str = ''
        for c in ciphertext:
            bit = self.decrypt_bit(c, private_key)
            binary_str += str(bit)

        # 根据输出类型转换
        if output_type == 'int':
            # 转换为整数
            if not binary_str:
                return 0
            return int(binary_str, 2)
        elif output_type == 'bytes':
            # 转换为bytes
            # 确保长度是8的倍数
            padding = (8 - len(binary_str) % 8) % 8
            binary_str = binary_str.zfill(len(binary_str) + padding)
            bytes_list = [int(binary_str[i:i + 8], 2) for i in range(0, len(binary_str), 8)]
            return bytes(bytes_list)
        elif output_type == 'str':
            # 转换为字符串
            bytes_data = self.decrypt(ciphertext, private_key, 'bytes')
            try:
                return bytes_data.decode('utf-8')
            except UnicodeDecodeError:
                return bytes_data.hex()
        else:
            raise ValueError("不支持的输出类型")

    def encrypt_32bit_int(self, num, public_key=None):
        """
        加密32位无符号整数（专门为比较协议设计）

        参数:
            num (int): 32位无符号整数
            public_key (tuple): (n, z)，如果为None则使用内部公钥

        返回:
            list: 加密后的32个密文，每个对应一个比特
        """
        if not isinstance(num, int):
            raise TypeError("输入必须是整数")
        if num < 0 or num >= 2 ** 32:
            raise ValueError("输入必须是32位无符号整数")

        # 转换为32位二进制字符串，高位补零
        binary_str = format(num, '032b')

        # 逐比特加密
        ciphertext = []
        for bit_char in binary_str:
            bit = int(bit_char)
            c = self.encrypt_bit(bit, public_key)
            ciphertext.append(c)

        return ciphertext

    def decrypt_32bit_int(self, ciphertext, private_key=None):
        """
        解密32位无符号整数（专门为比较协议设计）

        参数:
            ciphertext (list): 32个密文的列表
            private_key (tuple): (p, q)，如果为None则使用内部私钥

        返回:
            int: 解密后的32位无符号整数
        """
        if len(ciphertext) != 32:
            raise ValueError("密文长度必须是32")

        # 逐比特解密
        binary_str = ''
        for c in ciphertext:
            bit = self.decrypt_bit(c, private_key)
            binary_str += str(bit)

        # 转换为32位无符号整数
        return int(binary_str, 2)

    def batch_encrypt_bits(self, bits, public_key=None):
        """
        批量加密多个比特

        参数:
            bits (list): 比特列表（0或1）
            public_key (tuple): (n, z)，如果为None则使用内部公钥

        返回:
            list: 加密后的密文列表
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("公钥未生成，请先调用generate_keys()")
            public_key = self.public_key

        n, z = public_key
        ciphertext = []

        for bit in bits:
            # 选择随机数r，满足gcd(r, n) = 1
            while True:
                r = random.randint(1, n - 1)
                if math.gcd(r, n) == 1:
                    break

            if bit == 0:
                c = pow(r, 2, n)
            elif bit == 1:
                c = (pow(r, 2, n) * z) % n
            else:
                raise ValueError("比特必须是0或1")

            ciphertext.append(c)

        return ciphertext

    def __str__(self):
        """字符串表示"""
        return f"GoldwasserMicali(key_size={self.key_size}, public_key={self.public_key is not None}, private_key={self.private_key is not None})"

    def __repr__(self):
        """详细字符串表示"""
        return f"GoldwasserMicali(key_size={self.key_size}, public_key={self.public_key}, private_key={self.private_key})"


# 测试代码
if __name__ == "__main__":
    print("=== Goldwasser-Micali密码体制测试 (改进版) ===\n")

    # 创建GM实例
    gm = GoldwasserMicali(key_size=32)

    # 生成密钥
    print("1. 生成密钥...")
    public_key, private_key = gm.generate_keys()
    n, z = public_key
    p, q = private_key

    print(f"公钥 (n, z): {public_key}")
    print(f"私钥 (p, q): {private_key}")
    print(f"验证 p ≡ 3 mod 4: {p % 4 == 3}")
    print(f"验证 q ≡ 3 mod 4: {q % 4 == 3}")
    print(f"验证 n = p×q: {p * q == n}")
    print(f"验证雅可比符号(z|n) = +1: {gm.jacobi_symbol(z, n) == 1}")
    print(f"验证z是模p的非剩余: {gm.legendre_symbol(z % p, p) == -1}")
    print(f"验证z是模q的非剩余: {gm.legendre_symbol(z % q, q) == -1}")
    print()

    # 测试1: 加密解密32位整数
    print("2. 测试32位整数加密解密...")
    test_numbers = [0, 1, 123456789, 4294967295]  # 4294967295是2^32-1

    for num in test_numbers:
        print(f"\n测试数字: {num}")
        ciphertext = gm.encrypt_32bit_int(num)
        print(f"密文前5个元素: {ciphertext[:5]}...")
        decrypted_num = gm.decrypt_32bit_int(ciphertext)
        print(f"解密结果: {decrypted_num}")
        print(f"验证: {'成功' if decrypted_num == num else '失败'}")

    # 测试2: 加密解密字符串
    print("\n3. 测试字符串加密解密...")
    test_string = "Hello, Goldwasser-Micali!"
    print(f"原始字符串: {test_string}")

    ciphertext = gm.encrypt(test_string)
    print(f"密文长度: {len(ciphertext)}")
    print(f"密文前5个元素: {ciphertext[:5]}...")

    decrypted_string = gm.decrypt(ciphertext, output_type='str')
    print(f"解密字符串: {decrypted_string}")
    print(f"验证: {'成功' if decrypted_string == test_string else '失败'}")

    # 测试3: 批量加密
    print("\n4. 测试批量加密...")
    test_bits = [1, 0, 1, 0, 1, 1, 0, 0]
    print(f"原始比特: {test_bits}")

    ciphertext = gm.batch_encrypt_bits(test_bits)
    print(f"密文: {ciphertext}")

    decrypted_bits = [gm.decrypt_bit(c) for c in ciphertext]
    print(f"解密比特: {decrypted_bits}")
    print(f"验证: {'成功' if decrypted_bits == test_bits else '失败'}")

    print("\n=== 所有测试完成 ===")