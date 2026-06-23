import subprocess
import time
from scapy.all import sniff, ICMP, IP, conf

print("=== 实时抓包详细测试 ===")
print(f"管理员权限: {'是' if __import__('ctypes').windll.shell32.IsUserAnAdmin() else '否'}")

print("\n--- 接口列表 ---")
for iface_name, iface in conf.ifaces.items():
    friendly_name = iface.name or '未知'
    print(f"  {iface_name}: {friendly_name}")

print("\n--- 启动ping测试 ---")
ping_process = subprocess.Popen(
    ['ping', 'www.baidu.com', '-t'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
time.sleep(2)

print("\n--- 测试所有接口（每个3秒）---")
for iface_name, iface in conf.ifaces.items():
    friendly_name = iface.name or '未知'
    print(f"\n测试接口: {iface_name} ({friendly_name})")
    try:
        packet_count = []
        def callback(pkt):
            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
                direction = "发送" if pkt[IP].src.startswith('192.168') or pkt[IP].src.startswith('10.') or pkt[IP].src.startswith('172.') else "接收"
                print(f"  [{direction}] ICMP Type={icmp_type} ({'Request' if icmp_type == 8 else 'Reply' if icmp_type == 0 else '其他'})")
                packet_count.append(pkt)
        
        sniff(
            iface=iface_name,
            filter="icmp",
            timeout=3,
            count=10,
            prn=callback,
            store=False
        )
        print(f"  结果: 捕获到 {len(packet_count)} 个ICMP报文")
    except Exception as e:
        print(f"  失败: {e}")

ping_process.terminate()
ping_process.wait()

print("\n--- 测试完成 ---")