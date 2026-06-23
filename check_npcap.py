import subprocess

def check_npcap_service():
    services = ['npf', 'npcap']
    for service_name in services:
        try:
            result = subprocess.run(
                ['sc', 'query', service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f'[OK] Npcap服务({service_name})已安装！')
                for line in result.stdout.split('\n'):
                    if 'STATE' in line:
                        print(f'服务状态: {line.strip()}')
                return True
        except Exception:
            pass
    return False

def check_installation():
    import os
    install_dirs = [
        r'C:\Program Files\Npcap',
        r'C:\Program Files (x86)\Npcap'
    ]
    for dir_path in install_dirs:
        if os.path.exists(dir_path):
            print(f'[OK] Npcap安装目录存在: {dir_path}')
            return True
    return False

print('=== Npcap驱动检查 ===')

if not check_installation():
    print('[ERROR] Npcap安装目录不存在！')
    print('请访问 https://npcap.com/ 下载安装')
    print('安装时请勾选 "Install Npcap in WinPcap API-compatible Mode"')
    exit(1)

if not check_npcap_service():
    print('[ERROR] Npcap服务未注册！')
    print('尝试手动注册服务:')
    print(r'  sc create npcap binPath= "C:\Program Files\Npcap\npcap.sys" type= kernel start= auto')
    exit(1)

print('[OK] Npcap驱动安装完整！')
print('抓包功能可以正常使用。')