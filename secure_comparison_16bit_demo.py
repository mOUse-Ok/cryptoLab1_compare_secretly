#!/usr/bin/env python3
"""
简化版基于Goldwasser-Micali的16位秘密比较协议演示程序
专注于单次演示和完整的消息交换过程展示
"""

from secure_comparison_16bit import SecureComparisonProtocol_16bit


def main():
    """主函数：执行单次演示并展示完整消息交换过程"""
    print("=" * 80)
    print("简化版基于Goldwasser-Micali的16位秘密比较协议演示")
    print("=" * 80)
    print()

    # 输入两个秘密值
    a = int(input("请输入参与者A的秘密值a: "))
    b = int(input("请输入参与者B的秘密值b: "))

    print(f"\n参与者A的秘密输入: a = {a} (0x{a:04X})")
    print(f"参与者B的秘密输入: b = {b} (0x{b:04X})")
    print(f"实际关系: {a} < {b} = {a < b}")
    print()

    # 执行协议
    print("正在执行秘密比较协议...")
    print("-" * 80)

    # 运行协议并捕获所有消息
    t, A_messages, B_messages = SecureComparisonProtocol_16bit.run_protocol(a, b, verbose=False)

    # 合并并排序所有消息（按消息序号）
    all_messages = []
    for msg_idx, desc, content in A_messages:
        all_messages.append((msg_idx, "A", desc, content))
    for msg_idx, desc, content in B_messages:
        all_messages.append((msg_idx, "B", desc, content))

    # 按消息序号排序
    all_messages.sort()

    # 显示完整的消息交换过程
    print("完整的消息交换过程:")
    print("-" * 80)
    for msg_idx, sender, desc, content in all_messages:
        print(f"消息 #{msg_idx}: 参与者{sender} → 参与者{'B' if sender == 'A' else 'A'}")
        print(f"内容描述: {desc}")
        print(f"消息内容: {content}")
        print("-" * 80)

    # 显示最终结果
    print("\n协议执行完成！")
    print("=" * 80)
    print(f"最终比较结果: t = {t}")
    print(f"结果含义: {a} < {b} = {t == 1}")
    print(f"结果验证: {'✓ 正确' if t == (1 if a < b else 0) else '✗ 错误'}")
    print("=" * 80)


if __name__ == "__main__":
    main()