import subprocess
import threading
import time
import sys

print("测试抓包功能...")

try:
    from scapy.all import sniff, ICMP, conf
    print("[OK] scapy已安装")
except ImportError:
    print("[ERROR] scapy未安装")
    sys.exit(1)

try:
    import ctypes
    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
except:
    is_admin = False

print(f"管理员权限: {'是' if is_admin else '否'}")
if not is_admin:
    print("警告：需要管理员权限！")

# 获取回环接口
loopback_iface = None
for iface_name, iface in conf.ifaces.items():
    if 'Loopback' in iface.description or iface_name == '\\Device\\NPF_Loopback':
        loopback_iface = iface_name
        print(f"回环接口: {iface_name} ({iface.description})")
        break

if not loopback_iface:
    print("[ERROR] 未找到回环接口")
    sys.exit(1)

# 启动ping产生流量
print("\n启动ping 127.0.0.1...")
ping_process = subprocess.Popen(
    ['ping', '127.0.0.1', '-t'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# 等待ping开始
time.sleep(1)

# 测试抓包
print("\n在回环接口上抓包（5秒）...")
captured = []

try:
    packets = sniff(
        iface=loopback_iface,
        filter="icmp",
        timeout=5,
        count=10,
        prn=lambda x: None,
        store=True
    )
    
    for pkt in packets:
        if ICMP in pkt:
            captured.append((pkt[ICMP].type, pkt[ICMP].code))
    
    print(f"捕获到 {len(captured)} 个ICMP报文")
    
    if len(captured) > 0:
        type_counts = {}
        for t, c in captured:
            type_counts[t] = type_counts.get(t, 0) + 1
        
        print("\n报文类型统计:")
        from icmp_analyzer import ICMPAnalyzer
        analyzer = ICMPAnalyzer()
        for t, count in sorted(type_counts.items()):
            desc = analyzer.TYPE_DESCRIPTIONS.get(t, "未知")
            print(f"  Type {t}: {count} 个 ({desc})")
            
except Exception as e:
    print(f"[ERROR] 抓包失败: {e}")

# 停止ping
ping_process.terminate()
ping_process.wait()

print("\n测试完成！")