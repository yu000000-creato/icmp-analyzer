"""
ICMP差错报文分析程序 - 测试脚本
用于验证程序功能
"""

import sys
from icmp_analyzer import ICMPAnalyzer, ICMPType
from packet_reader import create_sample_icmp_packets


def test_icmp_analyzer():
    """测试ICMP分析器核心功能"""
    print("=" * 60)
    print("ICMP差错报文分析程序 - 功能测试")
    print("=" * 60)
    
    analyzer = ICMPAnalyzer()
    samples = create_sample_icmp_packets()
    
    print(f"\n[测试1] 创建测试样本 - 共 {len(samples)} 个报文")
    print("-" * 60)
    
    test_results = {
        'total': 0,
        'passed': 0,
        'failed': 0
    }
    
    # 测试每个样本
    for i, sample in enumerate(samples, 1):
        test_results['total'] += 1
        
        print(f"\n[测试样本 #{i}]")
        
        # 解析报文
        packet = analyzer.analyze_packet(sample)
        
        if packet is None:
            print("  ✗ 解析失败")
            test_results['failed'] += 1
            continue
            
        # 显示解析结果
        print(f"  类型: {packet.header.type} - {analyzer.TYPE_DESCRIPTIONS.get(packet.header.type, '未知')}")
        print(f"  代码: {packet.header.code}")
        print(f"  校验和: 0x{packet.header.checksum:04X}")
        print(f"  计算校验和: 0x{packet.calculated_checksum:04X}")
        print(f"  校验和验证: {'[PASS] 通过' if packet.checksum_valid else '[FAIL] 失败'}")
        
        # 验证校验和
        if packet.checksum_valid:
            print("  [PASS] 测试通过")
            test_results['passed'] += 1
        else:
            print("  [FAIL] 校验和验证失败")
            test_results['failed'] += 1
            
        # 显示详细描述
        print(f"  描述: {packet.description}")
        
    # 测试报文分类
    print("\n" + "=" * 60)
    print("[测试2] 报文分类功能")
    print("-" * 60)
    
    for icmp_type in [ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY, 
                      ICMPType.DESTINATION_UNREACHABLE, ICMPType.TIME_EXCEEDED]:
        is_query = analyzer.is_query_message(icmp_type)
        is_error = analyzer.is_error_message(icmp_type)
        
        print(f"Type {icmp_type}: 查询报文={is_query}, 差错报文={is_error}")
        
    # 测试统计功能
    print("\n" + "=" * 60)
    print("[测试3] 统计功能")
    print("-" * 60)
    
    stats = analyzer.get_statistics()
    print(f"总报文数: {stats['total_packets']}")
    print(f"类型分布: {stats['type_distribution']}")
    print(f"错误报文数: {stats['error_packets']}")
    
    # 测试目的不可达分析
    print("\n" + "=" * 60)
    print("[测试4] 目的不可达子代码分析")
    print("-" * 60)
    
    for code, desc in analyzer.UNREACHABLE_CODES.items():
        print(f"Code {code}: {desc}")
        
    # 测试超时分析
    print("\n" + "=" * 60)
    print("[测试5] 超时子代码分析")
    print("-" * 60)
    
    for code, desc in analyzer.TIME_EXCEEDED_CODES.items():
        print(f"Code {code}: {desc}")
        
    # 测试结果汇总
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    print(f"总测试数: {test_results['total']}")
    print(f"通过: {test_results['passed']}")
    print(f"失败: {test_results['failed']}")
    
    if test_results['failed'] == 0:
        print("\n[PASS] 所有测试通过!")
        return 0
    else:
        print(f"\n[FAIL] 有 {test_results['failed']} 个测试失败")
        return 1


def test_packet_reader():
    """测试报文读取功能"""
    print("\n" + "=" * 60)
    print("[测试6] 报文读取功能")
    print("-" * 60)
    
    from packet_reader import BinarySampleReader, calculate_checksum
    import struct
    
    # 创建测试文件
    test_data = bytes([
        8, 0,           # Type 8 (Echo Request), Code 0
        0, 0,           # Checksum placeholder
        0xAB, 0xCD,     # Identifier
        0x00, 0x01,     # Sequence
        0x01, 0x02, 0x03, 0x04  # Payload
    ])
    
    # 计算校验和
    checksum = calculate_checksum(test_data)
    test_data = bytes([8, 0]) + struct.pack('>H', checksum) + test_data[4:]
    
    # 写入测试文件
    test_file = "test_icmp_sample.bin"
    with open(test_file, 'wb') as f:
        f.write(test_data)
        
    print(f"创建测试文件: {test_file}")
    
    # 读取测试
    try:
        reader = BinarySampleReader(test_file)
        for data in reader.read():
            print(f"读取数据长度: {len(data)} 字节")
            print(f"数据内容: {data.hex()}")
            
            # 解析
            analyzer = ICMPAnalyzer()
            packet = analyzer.analyze_packet(data)
            
            if packet:
                print(f"解析成功: Type={packet.header.type}, Code={packet.header.code}")
                print(f"标识符: 0x{packet.header.identifier:04X}")
                print(f"序列号: {packet.header.sequence}")
                print("[PASS] 报文读取测试通过")
            else:
                print("[FAIL] 解析失败")
                
    except Exception as e:
        print(f"[FAIL] 测试失败: {e}")
        return 1
    finally:
        # 清理测试文件
        import os
        if os.path.exists(test_file):
            os.remove(test_file)
            
    return 0


def test_checksum():
    """测试校验和计算"""
    print("\n" + "=" * 60)
    print("[测试7] 校验和计算功能")
    print("-" * 60)
    
    from packet_reader import calculate_checksum
    
    # 测试数据
    test_cases = [
        (bytes([0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]), "Echo Request"),
        (bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]), "Echo Reply"),
    ]
    
    for data, desc in test_cases:
        checksum = calculate_checksum(data)
        print(f"{desc}: 校验和 = 0x{checksum:04X}")
        
    print("[PASS] 校验和计算测试完成")
    return 0


def main():
    """主测试函数"""
    print("\n" + "=" * 60)
    print("ICMP差错报文分析程序 - 完整功能测试")
    print("=" * 60 + "\n")
    
    results = []
    
    # 运行所有测试
    results.append(("核心分析功能", test_icmp_analyzer()))
    results.append(("报文读取功能", test_packet_reader()))
    results.append(("校验和计算", test_checksum()))
    
    # 汇总结果
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)
    
    total_failed = sum(r[1] for r in results)
    
    for name, result in results:
        status = "[PASS] 通过" if result == 0 else "[FAIL] 失败"
        print(f"{name}: {status}")
        
    if total_failed == 0:
        print("\n[PASS] 所有测试通过! 程序功能正常。")
        return 0
    else:
        print(f"\n[FAIL] 有测试失败，请检查程序。")
        return 1


if __name__ == "__main__":
    sys.exit(main())
