import subprocess
import sys
import time

print("测试WLAN接口抓包...")

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

# 获取接口映射
from packet_reader import get_interface_mapping
mapping = get_interface_mapping()

# 选择WLAN接口
selected_iface = "WLAN"
scapy_iface = mapping.get(selected_iface)

print(f"\n选择的接口: {selected_iface}")
print(f"Scapy接口名: {scapy_iface}")

if not scapy_iface:
    print("[ERROR] 未找到WLAN接口")
    sys.exit(1)

# 启动ping产生流量
print("\n启动ping www.baidu.com产生流量...")
ping_process = subprocess.Popen(
    ['ping', 'www.baidu.com', '-t'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
time.sleep(2)

# 测试抓包
print("\n开始抓包（5秒）...")
try:
    packets = sniff(
        iface=scapy_iface,
        filter="icmp",
        timeout=5,
        count=10,
        prn=lambda x: None,
        store=True
    )
    
    print(f"\n捕获到 {len(packets)} 个ICMP报文")
    
    if len(packets) > 0:
        from icmp_analyzer import ICMPAnalyzer
        analyzer = ICMPAnalyzer()
        
        print("\n报文详情:")
        for i, pkt in enumerate(packets):
            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
                icmp_code = pkt[ICMP].code
                desc = analyzer.TYPE_DESCRIPTIONS.get(icmp_type, "未知")
                print(f"  报文{i+1}: Type={icmp_type}, Code={icmp_code} ({desc})")
                
    else:
        print("\n没有捕获到报文")
        if not is_admin:
            print("原因: 没有管理员权限，无法访问物理网卡")
            print("请以管理员身份运行程序")
            
except PermissionError:
    print("\n[ERROR] 权限不足！")
    print("需要以管理员身份运行才能访问物理网卡")
    print("请右键点击命令提示符，选择'以管理员身份运行'")
except Exception as e:
    print(f"\n[ERROR] 抓包失败: {e}")

# 停止ping
ping_process.terminate()
ping_process.wait()

print("\n测试完成！")