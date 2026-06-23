"""
ICMP差错报文分析程序 - 主程序入口
支持命令行和图形界面两种模式
"""

import argparse
import sys
from pathlib import Path

from icmp_analyzer import ICMPAnalyzer
from packet_reader import (
    LivePacketReader, OfflinePacketReader, 
    create_sample_icmp_packets
)


def run_cli_mode(args):
    """命令行模式运行"""
    analyzer = ICMPAnalyzer()
    packets = []
    
    print("\n" + "=" * 60)
    print("ICMP差错报文分析程序")
    print("遵循RFC792协议标准")
    print("=" * 60 + "\n")
    
    # 根据模式读取报文
    if args.sample:
        print("[*] 使用测试样本进行分析...\n")
        samples = create_sample_icmp_packets()
        for i, data in enumerate(samples, 1):
            packet = analyzer.analyze_packet(data)
            if packet:
                packets.append(packet)
                print(f"--- 报文 #{i} ---")
                print(analyzer.format_output(packet))
                print()
                
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"[!] 错误: 文件不存在 - {args.file}")
            return 1
            
        print(f"[*] 从文件读取报文: {args.file}\n")
        
        try:
            reader = OfflinePacketReader(str(file_path))
            
            for i, data in enumerate(reader.read(), 1):
                packet = analyzer.analyze_packet(data)
                if packet:
                    packets.append(packet)
                    print(f"--- 报文 #{i} ---")
                    print(analyzer.format_output(packet))
                    print()
                    
        except Exception as e:
            print(f"[!] 读取文件失败: {e}")
            return 1
            
    elif args.live:
        print("[*] 开始实时抓包...\n")
        print("[!] 注意: 实时抓包需要管理员权限")
        print(f"[!] 接口: {args.interface if args.interface else '自动选择'}")
        print(f"[!] 超时: {args.timeout} 秒")
        print(f"[!] 数量: {args.count if args.count > 0 else '无限制'}\n")
        
        try:
            reader = LivePacketReader(
                interface=args.interface,
                timeout=args.timeout,
                packet_count=args.count
            )
            
            for i, data in enumerate(reader.read(), 1):
                packet = analyzer.analyze_packet(data)
                if packet:
                    packets.append(packet)
                    print(f"--- 报文 #{i} ---")
                    print(analyzer.format_output(packet))
                    print()
                    
        except PermissionError:
            print("[!] 错误: 需要管理员权限进行实时抓包")
            print("[!] 请以管理员身份运行程序")
            return 1
        except KeyboardInterrupt:
            print("\n[*] 用户中断抓包")
            
    else:
        print("[!] 请指定分析模式: --sample, --file <path>, 或 --live")
        return 1
        
    # 显示统计信息
    if packets:
        print("\n" + "=" * 60)
        print("统计信息")
        print("=" * 60)
        
        stats = analyzer.get_statistics()
        print(f"总报文数: {stats['total_packets']}")
        print(f"校验和错误报文数: {stats['error_packets']}")
        print()
        
        print("报文类型分布:")
        for type_num, count in sorted(stats['type_distribution'].items()):
            percentage = stats['type_percentages'][type_num]
            type_name = analyzer.TYPE_DESCRIPTIONS.get(type_num, "未知类型")
            print(f"  Type {type_num:2d} ({type_name[:20]}): {count:4d} ({percentage:5.1f}%)")
            
        # 导出结果
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write("ICMP报文分析结果\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for i, packet in enumerate(packets, 1):
                        f.write(f"报文 #{i}\n")
                        f.write(analyzer.format_output(packet))
                        f.write("\n\n")
                        
                print(f"\n[*] 结果已导出到: {args.output}")
            except Exception as e:
                print(f"[!] 导出失败: {e}")
                
    return 0


def run_gui_mode():
    """图形界面模式运行"""
    try:
        from gui import main
        main()
    except ImportError as e:
        print(f"[!] 无法启动图形界面: {e}")
        print("[!] 请确保已安装所有依赖")
        return 1
    return 0


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="ICMP差错报文分析程序 - 遵循RFC792协议标准",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用测试样本分析
  python main.py --sample
  
  # 分析pcap文件
  python main.py --file capture.pcap
  
  # 实时抓包分析
  python main.py --live --timeout 30 --count 100
  
  # 启动图形界面
  python main.py --gui
  
  # 导出分析结果
  python main.py --sample --output result.txt
        """
    )
    
    # 模式选择
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--gui', action='store_true', 
                           help='启动图形界面模式')
    mode_group.add_argument('--sample', action='store_true', 
                           help='使用测试样本进行分析')
    mode_group.add_argument('--file', type=str, metavar='PATH',
                           help='从pcap文件读取报文')
    mode_group.add_argument('--live', action='store_true', 
                           help='实时抓包模式')
    
    # 实时抓包参数
    parser.add_argument('--interface', '-i', type=str,
                       help='网卡接口名称')
    parser.add_argument('--timeout', '-t', type=int, default=10,
                       help='抓包超时时间(秒), 默认10秒')
    parser.add_argument('--count', '-c', type=int, default=0,
                       help='抓包数量, 0表示无限制')
    
    # 输出选项
    parser.add_argument('--output', '-o', type=str,
                       help='导出结果到文件')
    
    args = parser.parse_args()
    
    # 默认启动图形界面
    if not (args.gui or args.sample or args.file or args.live):
        args.gui = True
        
    if args.gui:
        return run_gui_mode()
    else:
        return run_cli_mode(args)


if __name__ == "__main__":
    sys.exit(main())
