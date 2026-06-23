import subprocess
import sys
import time

print("测试以太网接口抓包...")

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

from packet_reader import get_interface_mapping
mapping = get_interface_mapping()

eth_iface = mapping.get('以太网')
print(f"\n以太网接口: {eth_iface}")

# 检查接口状态
for iface_name, iface in conf.ifaces.items():
    if iface_name == eth_iface:
        print(f"描述: {iface.description}")
        print(f"IP: {iface.ip}")
        print(f"MAC: {iface.mac}")
        break

# 检查以太网是否连接
result = subprocess.run(
    ['ipconfig'],
    capture_output=True, text=True, encoding='gbk', errors='ignore'
)
for line in result.stdout.split('\n'):
    if '以太网' in line or 'Realtek' in line:
        print(f"  {line.strip()}")

print("\n启动ping www.baidu.com产生流量...")
ping_process = subprocess.Popen(
    ['ping', 'www.baidu.com', '-t'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
time.sleep(2)

print("\n开始抓包（5秒）...")
try:
    packets = sniff(
        iface=eth_iface,
        filter="icmp",
        timeout=5,
        count=10,
        prn=lambda x: None,
        store=True
    )
    
    print(f"\n捕获到 {len(packets)} 个ICMP报文")
    
    if len(packets) > 0:
        for i, pkt in enumerate(packets[:5]):
            if ICMP in pkt:
                print(f"  报文{i+1}: Type={pkt[ICMP].type}, Code={pkt[ICMP].code}")
    else:
        print("\n没有捕获到报文")
        print("可能原因:")
        print("  1. 以太网未连接（没有网线）")
        print("  2. 网络流量走的是WLAN接口")
        print("  3. 防火墙阻止")
        
except Exception as e:
    print(f"\n[ERROR] 抓包失败: {e}")

ping_process.terminate()
ping_process.wait()

print("\n测试完成！")