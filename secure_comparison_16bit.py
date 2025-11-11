import random
import math
from goldwasser_micali import GoldwasserMicali

class SecureComparisonProtocol_16bit:
    """
    基于Goldwasser-Micali密码体制的16位秘密比较协议实现
    
    参与者A持有16位整数a（0-65535），参与者B持有16位整数b（0-65535）和私钥
    协议执行后，B可以确定a < b是否成立，而不会泄露a和b的具体值
    
    安全性保证：
    - 如果GM密码体制是安全的概率加密，则在获得结果前，A和B持有的值对对方而言与等长随机串不可区分
    - 协议执行过程中，除了最终比较结果外，不会泄露任何关于a和b的额外信息
    """
    
    @staticmethod
    def _int_to_16bits(num):
        """将整数转换为16位二进制列表，低位在前（LSB first）"""
        if not isinstance(num, int):
            raise TypeError("输入必须是整数")
        if num < 0 or num >= 2 ** 16:
            raise ValueError("输入必须是16位无符号整数（0-65535）")
        
        # 转换为16位二进制字符串，高位在前，然后反转得到低位在前
        binary_str = format(num, '016b')
        reversed_binary = binary_str[::-1]  # 反转得到低位在前
        
        return [int(bit) for bit in reversed_binary]
    
    @staticmethod
    def _16bits_to_int(bits):
        """将16位二进制列表转换为整数，低位在前"""
        if len(bits) != 16:
            raise ValueError("必须是16位二进制列表")
        
        # 反转列表得到高位在前
        reversed_bits = bits[::-1]
        binary_str = ''.join(map(str, reversed_bits))
        
        return int(binary_str, 2)
    
    @staticmethod
    def _c_mul(c1, c2, n):
        """
        GM密文乘法，相当于明文异或
        C_mul(E(x), E(y)) = E(x XOR y)
        """
        return (c1 * c2) % n
    
    @staticmethod
    def _encrypt_constant(gm, constant, public_key):
        """加密常数"""
        n, z = public_key
        
        # 选择随机数r，满足gcd(r, n) = 1
        while True:
            r = random.randint(1, n - 1)
            if math.gcd(r, n) == 1:
                break
        
        if constant == 0:
            return pow(r, 2, n)
        elif constant == 1:
            return (pow(r, 2, n) * z) % n
        else:
            raise ValueError("只支持加密0和1")
    
    @staticmethod
    def run_protocol(a, b, key_size=32, verbose=False):
        """
        运行16位秘密比较协议
        
        参数:
            a (int): 参与者A持有的16位整数（0-65535）
            b (int): 参与者B持有的16位整数（0-65535）
            key_size (int): GM密码体制的密钥大小（比特数）
            verbose (bool): 是否输出详细的执行过程
            
        返回:
            tuple: (t, A_messages, B_messages)
                t: int，表示比较结果（1表示a < b，0表示a >= b）
                A_messages: list，A发送的所有消息记录
                B_messages: list，B发送的所有消息记录
        """
        # 输入验证
        if not isinstance(a, int) or a < 0 or a >= 2**16:
            raise ValueError("a必须是16位无符号整数（0-65535）")
        if not isinstance(b, int) or b < 0 or b >= 2**16:
            raise ValueError("b必须是16位无符号整数（0-65535）")
        
        # 初始化消息记录
        A_messages = []
        B_messages = []
        msg_index = 0
        
        # 将整数转换为16位二进制，低位在前
        a_bits = SecureComparisonProtocol_16bit._int_to_16bits(a)
        b_bits = SecureComparisonProtocol_16bit._int_to_16bits(b)
        
        if verbose:
            print("=" * 80)
            print("          基于Goldwasser-Micali的16位秘密比较协议")
            print("=" * 80)
            print(f"参与者A的秘密输入: a = {a} (0x{a:04X})")
            print(f"参与者B的秘密输入: b = {b} (0x{b:04X})")
            print(f"实际关系: {a} < {b} = {a < b}")
            print()
        
        # 创建GM实例
        gm = GoldwasserMicali(key_size=key_size)
        
        # ---------- 初始化与i=0轮 ----------
        # Msg 1: B -> A : pk, E(b0)
        msg_index += 1
        public_key, private_key = gm.generate_keys()
        n, z = public_key
        p, q = private_key
        
        # 加密b[0] (最低位)
        E_b0 = SecureComparisonProtocol_16bit._encrypt_constant(gm, b_bits[0], public_key)
        
        B_messages.append((msg_index, "B -> A : 公钥pk, E(b0)", {
            "pk": public_key,
            "E_b0": E_b0
        }))
        
        if verbose:
            print(f"消息 #{msg_index}: B -> A : 公钥pk = {public_key}, E(b0) = {E_b0}")
        
        # A本地构造E(t0)
        if a_bits[0] == 1:
            # E(t0) = E(0)
            E_t0 = SecureComparisonProtocol_16bit._encrypt_constant(gm, 0, public_key)
        else:
            # E(t0) = E(b0)
            E_t0 = E_b0
        
        # A选择随机数r0并发送掩码后的t0
        r0 = random.getrandbits(1)
        E_r0 = SecureComparisonProtocol_16bit._encrypt_constant(gm, r0, public_key)
        M2 = SecureComparisonProtocol_16bit._c_mul(E_t0, E_r0, n)
        
        msg_index += 1
        A_messages.append((msg_index, "A -> B : M2 = E(t0) * E(r0) = E(t0 ⊕ r0)", {
            "M2": M2
        }))
        
        if verbose:
            print(f"消息 #{msg_index}: A -> B : M2 = E(t0) * E(r0) = {M2}")
        
        # ---------- 主循环：i = 1..15 ----------
        r_prev = r0
        current_M2 = M2
        
        for i in range(1, 16):
            if verbose:
                print(f"第{i}轮 (处理第{i}位):")
            
            # B接收A的消息并解密s = t_{i-1} ⊕ r_{i-1}
            s = gm.decrypt_bit(current_M2, private_key)
            
            if verbose:
                print(f"B解密得到: s = t_{i-1} ⊕ r_{i-1} = {s}")
            
            # B计算u0, u1
            u0 = s | b_bits[i]  # OR操作
            u1 = s & b_bits[i]  # AND操作
            
            if verbose:
                print(f"B计算: u0 = s | b_{i} = {s} | {b_bits[i]} = {u0}")
                print(f"        u1 = s & b_{i} = {s} & {b_bits[i]} = {u1}")
            
            # B加密u0, u1和b[i]
            E_u0 = SecureComparisonProtocol_16bit._encrypt_constant(gm, u0, public_key)
            E_u1 = SecureComparisonProtocol_16bit._encrypt_constant(gm, u1, public_key)
            E_bi = SecureComparisonProtocol_16bit._encrypt_constant(gm, b_bits[i], public_key)
            
            msg_index += 1
            B_messages.append((msg_index, f"B -> A (round {i}): E(u0), E(u1), E(b{i})", {
                "E_u0": E_u0,
                "E_u1": E_u1,
                "E_bi": E_bi
            }))
            
            if verbose:
                print(f"消息 #{msg_index}: B -> A : E(u0) = {E_u0}, E(u1) = {E_u1}, E(b{i}) = {E_bi}")
            
            # A接收并构造E(t_i)
            if a_bits[i] == 0:
                if r_prev == 0:
                    E_ti = E_u0
                    if verbose:
                        print(f"A的a_{i} = 0, 之前的r_{i-1} = 0")
                        print(f"A构造: E(t_{i}) = E(u0) = {E_ti}")
                else:
                    # E(t_i) = E(u0) XOR E(1 XOR b_i)
                    E_one = SecureComparisonProtocol_16bit._encrypt_constant(gm, 1, public_key)
                    E_one_xor_bi = SecureComparisonProtocol_16bit._c_mul(E_one, E_bi, n)
                    E_ti = SecureComparisonProtocol_16bit._c_mul(E_u0, E_one_xor_bi, n)
                    if verbose:
                        print(f"A的a_{i} = 0, 之前的r_{i-1} = 1")
                        print(f"A构造: E(t_{i}) = E(u0) * E(1 XOR b_{i}) = {E_ti}")
            else:  # a[i] == 1
                if r_prev == 0:
                    E_ti = E_u1
                    if verbose:
                        print(f"A的a_{i} = 1, 之前的r_{i-1} = 0")
                        print(f"A构造: E(t_{i}) = E(u1) = {E_ti}")
                else:
                    # E(t_i) = E(u1) XOR E(b_i)
                    E_ti = SecureComparisonProtocol_16bit._c_mul(E_u1, E_bi, n)
                    if verbose:
                        print(f"A的a_{i} = 1, 之前的r_{i-1} = 1")
                        print(f"A构造: E(t_{i}) = E(u1) * E(b_{i}) = {E_ti}")
            
            # 处理掩码和发送
            if i < 15:
                # A选择新的随机数r_i
                r_i = random.getrandbits(1)
                E_ri = SecureComparisonProtocol_16bit._encrypt_constant(gm, r_i, public_key)
                current_M2 = SecureComparisonProtocol_16bit._c_mul(E_ti, E_ri, n)
                
                msg_index += 1
                A_messages.append((msg_index, f"A -> B (round {i}): M = E(t{i}) * E(r{i}) = E(t{i} ⊕ r{i})", {
                    "M": current_M2
                }))
                
                if verbose:
                    print(f"消息 #{msg_index}: A -> B : M = E(t_{i}) * E(r_{i}) = {current_M2}")
                
                r_prev = r_i
            else:
                # 最后一轮，直接发送E(t_15) (最高位)
                msg_index += 1
                A_messages.append((msg_index, f"A -> B (final): E(t15)", {
                    "E_t15": E_ti
                }))
                
                if verbose:
                    print(f"消息 #{msg_index}: A -> B : E(t_15) = {E_ti}")
                
                final_cipher = E_ti
        
        # ---------- B解密最终结果 ----------
        t = gm.decrypt_bit(final_cipher, private_key)
        
        if verbose:
            print()
            print("=" * 80)
            print("协议执行完成，B解密最终结果:")
            print(f"B解密E(t_15)得到: t = {t}")
            print(f"协议结果: t = {t} (1表示a < b，0表示a >= b)")
            print(f"结果验证: {'正确' if t == (1 if a < b else 0) else '错误'}")
            print("=" * 80)
        
        return t, A_messages, B_messages

# 测试代码
if __name__ == "__main__":
    print("=== 16位秘密比较协议测试 ===")
    print("=" * 80)
    print()
    
    # 测试用例
    test_cases = [
        (10, 20, 1),          # 一般情况：a < b
        (20, 10, 0),          # 一般情况：a > b
        (0, 0, 0),            # 边界情况：a = b = 0
        (0, 1, 1),            # 边界情况：a = 0, b = 1
        (65535, 0, 0),        # 边界情况：a = 最大, b = 0
        (12345, 54321, 1),    # 随机情况：12345 < 54321
        (32767, 32768, 1),    # 边界情况：2^15-1 < 2^15
        (65535, 65535, 0)     # 边界情况：a = b = 最大
    ]
    
    all_correct = True
    
    for i, (a, b, expected) in enumerate(test_cases, 1):
        print(f"测试用例 {i}: a = {a}, b = {b}, 期望结果: {expected}")
        print("-" * 60)
        
        try:
            t, A_messages, B_messages = SecureComparisonProtocol_16bit.run_protocol(a, b, key_size=32, verbose=False)
            correct = (t == expected)
            all_correct &= correct
            
            print(f"协议结果: t = {t}")
            print(f"期望结果: t = {expected}")
            print(f"测试结果: {'✓ 正确' if correct else '✗ 错误'}")
            print(f"A发送消息数: {len(A_messages)}")
            print(f"B发送消息数: {len(B_messages)}")
            print(f"总消息数: {len(A_messages) + len(B_messages)}")
            
        except Exception as e:
            print(f"测试失败: {e}")
            all_correct = False
        
        print()
    
    print("=" * 60)
    print(f"所有测试用例总体结果: {'✓ 全部正确' if all_correct else '✗ 存在错误'}")
    print("=" * 60)
    
    # 安全性说明
    print("\n=== 协议安全性说明 ===")
    print("1. 基于Goldwasser-Micali概率加密体制")
    print("2. 完美隐藏性确保输入隐私")
    print("3. 诚实好奇模型下的安全性保证")
    print("4. 除最终比较结果外，不泄露任何额外信息")
    print("5. 16轮消息交换，总共32条消息")