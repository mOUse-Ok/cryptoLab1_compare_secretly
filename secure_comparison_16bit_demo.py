#!/usr/bin/env python3
"""
基于Goldwasser-Micali的16位秘密比较协议演示程序

这个程序专门展示16位版本的秘密比较协议，包括详细的执行过程和结果验证。
"""

from secure_comparison_16bit import SecureComparisonProtocol_16bit

def basic_demo():
    """基本演示：简单的协议使用"""
    print("=" * 80)
    print("          基本演示：16位秘密比较协议")
    print("=" * 80)
    
    # 示例输入
    a = 12345
    b = 54321
    
    print(f"参与者A的秘密输入: a = {a} (0x{a:04X})")
    print(f"参与者B的秘密输入: b = {b} (0x{b:04X})")
    print(f"实际关系: {a} < {b} = {a < b}")
    print()
    
    # 运行协议
    print("执行协议...")
    t, A_messages, B_messages = SecureComparisonProtocol_16bit.run_protocol(a, b)
    
    print(f"\n协议结果: t = {t}")
    print(f"结果含义: {a} < {b} = {t == 1}")
    print(f"结果验证: {'正确' if t == (1 if a < b else 0) else '错误'}")
    print()
    
    print(f"消息统计:")
    print(f"- A发送的消息数: {len(A_messages)}")
    print(f"- B发送的消息数: {len(B_messages)}")
    print(f"- 总消息数: {len(A_messages) + len(B_messages)}")

def detailed_demo():
    """详细演示：展示协议的完整执行过程"""
    print("\n" + "=" * 80)
    print("          详细演示：协议执行过程")
    print("=" * 80)
    
    a = 32767
    b = 32768
    
    print(f"参与者A的秘密输入: a = {a} (0x{a:04X})")
    print(f"参与者B的秘密输入: b = {b} (0x{b:04X})")
    print(f"实际关系: {a} < {b} = {a < b}")
    print()
    
    # 运行协议并显示详细过程
    print("执行协议（详细模式）...")
    t, A_messages, B_messages = SecureComparisonProtocol_16bit.run_protocol(a, b, verbose=True)
    
    print(f"\n协议结果: t = {t}")
    print(f"结果含义: {a} < {b} = {t == 1}")
    print(f"结果验证: {'正确' if t == (1 if a < b else 0) else '错误'}")

def message_analysis_demo():
    """消息分析演示：展示所有交换的消息"""
    print("\n" + "=" * 80)
    print("          消息分析演示：查看所有交换的消息")
    print("=" * 80)
    
    a = 10
    b = 20
    
    print(f"参与者A的秘密输入: a = {a}")
    print(f"参与者B的秘密输入: b = {b}")
    print()
    
    # 运行协议
    t, A_messages, B_messages = SecureComparisonProtocol_16bit.run_protocol(a, b, verbose=False)
    
    print("A发送的消息:")
    print("-" * 50)
    for msg_idx, desc, content in A_messages:
        print(f"消息 #{msg_idx}: {desc}")
        print(f"内容: {content}")
        print()
    
    print("B发送的消息:")
    print("-" * 50)
    for msg_idx, desc, content in B_messages:
        print(f"消息 #{msg_idx}: {desc}")
        print(f"内容: {content}")
        print()

def multiple_test_cases_demo():
    """多测试用例演示：测试各种情况"""
    print("\n" + "=" * 80)
    print("          多测试用例演示：测试各种比较情况")
    print("=" * 80)
    
    test_cases = [
        (10, 20, "一般情况：a < b"),
        (20, 10, "一般情况：a > b"),
        (0, 0, "边界情况：a = b = 0"),
        (0, 1, "边界情况：a = 0, b = 1"),
        (65535, 0, "边界情况：a = 最大, b = 0"),
        (65535, 65535, "边界情况：a = b = 最大"),
        (32767, 32768, "边界情况：2^15-1 < 2^15"),
        (12345, 54321, "随机情况：12345 < 54321")
    ]
    
    all_correct = True
    
    for i, (a, b, description) in enumerate(test_cases, 1):
        print(f"\n测试用例 {i}: {description}")
        print(f"a = {a}, b = {b}")
        print("-" * 40)
        
        t, _, _ = SecureComparisonProtocol_16bit.run_protocol(a, b, verbose=False)
        expected = 1 if a < b else 0
        correct = t == expected
        
        print(f"协议结果: t = {t}")
        print(f"期望结果: t = {expected}")
        print(f"测试结果: {'✓ 正确' if correct else '✗ 错误'}")
        
        if not correct:
            all_correct = False
    
    print(f"\n{'=' * 50}")
    print(f"所有测试用例总体结果: {'✓ 全部正确' if all_correct else '✗ 存在错误'}")

def performance_test_demo():
    """性能测试演示：测试协议的执行时间"""
    print("\n" + "=" * 80)
    print("          性能测试演示：测试协议执行时间")
    print("=" * 80)
    
    import time
    
    test_sizes = [16, 32, 64]  # 不同的密钥大小
    
    for key_size in test_sizes:
        print(f"\n密钥大小: {key_size} 位")
        print("-" * 40)
        
        # 测试多次取平均值
        total_time = 0
        num_tests = 5
        
        for _ in range(num_tests):
            start_time = time.time()
            SecureComparisonProtocol_16bit.run_protocol(12345, 54321, key_size=key_size, verbose=False)
            end_time = time.time()
            total_time += (end_time - start_time)
        
        avg_time = total_time / num_tests
        print(f"平均执行时间: {avg_time:.4f} 秒")
        print(f"消息交换次数: 32 次")

def security_explanation_demo():
    """安全性说明演示：解释协议的安全性"""
    print("\n" + "=" * 80)
    print("          安全性说明：为什么协议是安全的")
    print("=" * 80)
    
    print("\n1. 基于困难数学问题:")
    print("   - 二次剩余问题(QRP)：无法有效区分二次剩余和非剩余")
    print("   - 大整数分解问题：无法有效分解大素数乘积")
    print()
    
    print("2. 完美隐藏性:")
    print("   - 同一明文会产生不同的密文")
    print("   - 密文与随机数在计算上不可区分")
    print("   - 攻击者无法从密文推断明文信息")
    print()
    
    print("3. 隐私保护:")
    print("   - A的输入a对B完全保密")
    print("   - B的输入b对A完全保密")
    print("   - 只泄露比较结果，不泄露具体数值")
    print()
    
    print("4. 诚实好奇模型:")
    print("   - 假设双方诚实地执行协议")
    print("   - 即使双方分析所有消息，也无法推断对方输入")

def main():
    """主函数：运行所有演示"""
    print("=" * 80)
    print("基于Goldwasser-Micali的16位秘密比较协议完整演示")
    print("=" * 80)
    print()
    
    # 运行各个演示模块
    basic_demo()
    detailed_demo()
    message_analysis_demo()
    multiple_test_cases_demo()
    performance_test_demo()
    security_explanation_demo()
    
    print("\n" + "=" * 80)
    print("演示完成！")
    print("=" * 80)

if __name__ == "__main__":
    main()