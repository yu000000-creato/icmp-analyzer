"""
ICMP差错报文分析程序 - 报文读取模块
支持实时网卡抓包和离线pcap文件读取
基于Scapy+Npcap实现
"""

import socket
import struct
import time
from typing import Optional, List, Generator, Callable
from pathlib import Path

from scapy.all import sniff, rdpcap, IP, ICMP, conf
from utils import calculate_checksum


class PacketReader:
    """报文读取器基类"""
    
    def __init__(self):
        self.packets: List[bytes] = []
        
    def read(self) -> Generator[bytes, None, None]:
        """读取报文生成器"""
        raise NotImplementedError


class LivePacketReader(PacketReader):
    """实时网卡抓包读取器"""
    
    def __init__(self, interface: Optional[str] = None, timeout: int = 0, 
                 packet_count: int = 0):
        """
        初始化实时抓包读取器
        
        Args:
            interface: 网卡接口名称，None表示自动选择
            timeout: 最大抓包时间（秒），0表示无限制
            packet_count: 抓包数量，0表示无限制
        """
        super().__init__()
        self.interface = interface
        self.timeout = timeout
        self.packet_count = packet_count
        self._callback: Optional[Callable] = None
        self._stopped = False
        self._start_time = 0
        
    def read(self) -> Generator[bytes, None, None]:
        """实时抓取ICMP报文（使用Scapy+Npcap）"""
        yield from self._read_with_scapy()
    
    def stop(self):
        """停止抓包"""
        self._stopped = True
    
    def _read_with_scapy(self) -> Generator[bytes, None, None]:
        """使用Scapy进行抓包（实时返回）"""
        try:
            iface_to_use = self.interface
            if self.interface:
                mapping = get_interface_mapping()
                if self.interface in mapping:
                    iface_to_use = mapping[self.interface]
            
            packet_index = 0
            self._start_time = time.time()
            
            timeout_value = 1 if self.timeout == 0 else min(self.timeout, 1)
            
            while not self._stopped:
                packets = sniff(
                    iface=iface_to_use,
                    filter="icmp",
                    timeout=timeout_value,
                    count=5,
                    prn=lambda x: None,
                    store=True
                )
                
                for pkt in packets:
                    if self._stopped:
                        break
                    if ICMP in pkt:
                        packet_index += 1
                        icmp_bytes = bytes(pkt[ICMP])
                        yield icmp_bytes
                
                if self.packet_count > 0 and packet_index >= self.packet_count:
                    break
                
                if self.timeout > 0 and (time.time() - self._start_time) >= self.timeout:
                    break
                    
        except PermissionError:
            raise PermissionError("实时抓包需要管理员权限。请以管理员身份运行程序。")
        except Exception as e:
            raise RuntimeError(f"Scapy抓包失败: {e}")
    
    def set_callback(self, callback: Callable):
        """设置回调函数"""
        self._callback = callback


class OfflinePacketReader(PacketReader):
    """离线pcap文件读取器"""
    
    def __init__(self, file_path: str):
        """
        初始化离线文件读取器
        
        Args:
            file_path: pcap文件路径
        """
        super().__init__()
        self.file_path = Path(file_path)
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
    
    def read(self) -> Generator[bytes, None, None]:
        """从pcap文件读取ICMP报文"""
        yield from self._read_with_scapy()
    
    def _read_with_scapy(self) -> Generator[bytes, None, None]:
        """使用Scapy读取pcap文件"""
        try:
            packets = rdpcap(str(self.file_path))
            
            for pkt in packets:
                if ICMP in pkt:
                    yield bytes(pkt[ICMP])
                elif IP in pkt and pkt[IP].proto == 1:
                    ip_header_len = pkt[IP].ihl * 4
                    icmp_data = bytes(pkt[IP])[ip_header_len:]
                    if len(icmp_data) >= 8:
                        yield icmp_data
                elif 'Raw' in type(pkt).__name__:
                    raw_data = bytes(pkt)
                    if len(raw_data) >= 14:
                        eth_type = (raw_data[12] << 8) | raw_data[13]
                        if eth_type == 0x0800 and len(raw_data) >= 34:
                            ip_data = raw_data[14:]
                            ip_version = (ip_data[0] >> 4) & 0x0F
                            if ip_version == 4:
                                ip_header_len = (ip_data[0] & 0x0F) * 4
                                protocol = ip_data[9]
                                if protocol == 1 and len(ip_data) >= ip_header_len + 8:
                                    yield ip_data[ip_header_len:]
                        elif len(raw_data) >= 20:
                            ip_version = (raw_data[0] >> 4) & 0x0F
                            if ip_version == 4:
                                ip_header_len = (raw_data[0] & 0x0F) * 4
                                protocol = raw_data[9]
                                if protocol == 1 and len(raw_data) >= ip_header_len + 8:
                                    yield raw_data[ip_header_len:]
                    
        except Exception as e:
            raise RuntimeError(f"读取pcap文件失败: {e}")
    
    def _read_binary(self) -> Generator[bytes, None, None]:
        """读取二进制格式的ICMP报文样本"""
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            if data[:4] == b'\xd4\xc3\xb2\xa1':
                yield from self._parse_pcap(data)
            elif data[:4] == b'\xa1\xb2\xc3\xd4':
                yield from self._parse_pcap(data, big_endian=True)
            else:
                yield data
                
        except Exception as e:
            raise RuntimeError(f"读取文件失败: {e}")
    
    def _parse_pcap(self, data: bytes, big_endian: bool = False) -> Generator[bytes, None, None]:
        """解析pcap文件格式"""
        endian = '>' if big_endian else '<'
        offset = 24
        
        while offset < len(data):
            if offset + 16 > len(data):
                break
                
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f'{endian}IIII', data[offset:offset+16]
            )
            offset += 16
            
            if offset + incl_len > len(data):
                break
                
            packet_data = data[offset:offset+incl_len]
            offset += incl_len
            
            if len(packet_data) < 14:
                continue
                
            eth_type = struct.unpack('>H', packet_data[12:14])[0]
            
            if eth_type != 0x0800:
                continue
                
            ip_data = packet_data[14:]
            if len(ip_data) < 20:
                continue
                
            ip_header_length = (ip_data[0] & 0x0F) * 4
            protocol = ip_data[9]
            
            if protocol != 1:
                continue
                
            icmp_data = ip_data[ip_header_length:]
            if len(icmp_data) >= 8:
                yield icmp_data


class BinarySampleReader(PacketReader):
    """二进制样本读取器"""
    
    def __init__(self, file_path: str):
        """
        初始化二进制样本读取器
        
        Args:
            file_path: 二进制文件路径
        """
        super().__init__()
        self.file_path = Path(file_path)
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"文件不存在: {file_path}")
    
    def read(self) -> Generator[bytes, None, None]:
        """读取二进制ICMP样本"""
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        if len(data) >= 8:
            yield data


def get_network_interfaces() -> List[str]:
    """获取可用的网络接口列表（返回中文友好名称）"""
    interfaces = []
    interface_set = set()
    
    for iface_name, iface in conf.ifaces.items():
        friendly_name = iface.name or ''
        description = iface.description or ''
        
        if '本地连接*' in friendly_name:
            continue
        
        display_name = friendly_name
        
        if 'Loopback' in description or '回环' in description:
            display_name = '回环接口'
        elif 'Wi-Fi' in description and 'Direct' not in description:
            if friendly_name != 'WLAN':
                display_name = 'WLAN'
        elif 'Ethernet' in description or '以太网' in description:
            if friendly_name != '以太网':
                display_name = '以太网'
        
        if display_name and display_name not in interface_set:
            interface_set.add(display_name)
            interfaces.append(display_name)
    
    if not interfaces:
        interfaces = ['回环接口', 'WLAN', '以太网']
    
    preferred_order = ['回环接口', 'WLAN', '以太网', 'CloudflareWARP', '蓝牙网络连接']
    ordered_interfaces = []
    for name in preferred_order:
        if name in interface_set:
            ordered_interfaces.append(name)
            interface_set.remove(name)
    ordered_interfaces.extend(list(interface_set))
    
    return ordered_interfaces


def get_interface_mapping() -> dict:
    """获取接口中文名称到scapy接口名的映射"""
    mapping = {}
    
    for iface_name, iface in conf.ifaces.items():
        friendly_name = iface.name or ''
        description = iface.description or ''
        
        if 'Loopback' in description or '回环' in description:
            mapping['回环接口'] = iface_name
        elif friendly_name == 'WLAN':
            mapping['WLAN'] = iface_name
        elif friendly_name == '以太网':
            mapping['以太网'] = iface_name
        elif friendly_name == 'CloudflareWARP':
            mapping['CloudflareWARP'] = iface_name
        elif friendly_name == '蓝牙网络连接':
            mapping['蓝牙网络连接'] = iface_name
        elif 'Wi-Fi' in description and 'Direct' not in description:
            if 'WLAN' not in mapping:
                mapping['WLAN'] = iface_name
        elif 'Ethernet' in description:
            if '以太网' not in mapping:
                mapping['以太网'] = iface_name
    
    return mapping


def create_sample_icmp_packets() -> List[bytes]:
    """创建示例ICMP报文用于测试"""
    samples = []
    
    echo_request = bytes([
        8, 0,
        0, 0,
        0x12, 0x34,
        0x00, 0x01,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
    ])
    checksum = calculate_checksum(echo_request)
    echo_request = bytes([8, 0]) + struct.pack('>H', checksum) + echo_request[4:]
    samples.append(echo_request)
    
    echo_reply = bytes([
        0, 0,
        0, 0,
        0x12, 0x34,
        0x00, 0x01,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68
    ])
    checksum = calculate_checksum(echo_reply)
    echo_reply = bytes([0, 0]) + struct.pack('>H', checksum) + echo_reply[4:]
    samples.append(echo_reply)
    
    dest_unreach_codes = [0, 1, 2, 3, 4, 5]
    for code in dest_unreach_codes:
        dest_unreach = bytes([
            3, code,
            0, 0,
            0, 0,
            0, 0,
            0, 0, 0, 0,
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1,
            192, 168, 1, 2,
            0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01
        ])
        checksum = calculate_checksum(dest_unreach)
        dest_unreach = bytes([3, code]) + struct.pack('>H', checksum) + dest_unreach[4:]
        samples.append(dest_unreach)
    
    source_quench = bytes([
        4, 0,
        0, 0,
        0, 0,
        0, 0,
        0, 0, 0, 0,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2,
        0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01
    ])
    checksum = calculate_checksum(source_quench)
    source_quench = bytes([4, 0]) + struct.pack('>H', checksum) + source_quench[4:]
    samples.append(source_quench)
    
    redirect_codes = [0, 1, 2, 3]
    for code in redirect_codes:
        redirect = bytes([
            5, code,
            0, 0,
            10, 0, 0, 10,
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 1,
            192, 168, 1, 2,
            0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01
        ])
        checksum = calculate_checksum(redirect)
        redirect = bytes([5, code]) + struct.pack('>H', checksum) + redirect[4:]
        samples.append(redirect)
    
    time_exceeded = bytes([
        11, 0,
        0, 0,
        0, 0,
        0, 0,
        0, 0, 0, 0,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x01, 0x06, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2,
        0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01
    ])
    checksum = calculate_checksum(time_exceeded)
    time_exceeded = bytes([11, 0]) + struct.pack('>H', checksum) + time_exceeded[4:]
    samples.append(time_exceeded)
    
    frag_reassembly_timeout = bytes([
        11, 1,
        0, 0,
        0, 0,
        0, 0,
        0, 0, 0, 0,
        0x45, 0x00, 0x05, 0xDC,
        0x12, 0x34, 0x00, 0x01,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 10, 10,
        203, 0, 113, 1,
        0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01
    ])
    checksum = calculate_checksum(frag_reassembly_timeout)
    frag_reassembly_timeout = bytes([11, 1]) + struct.pack('>H', checksum) + frag_reassembly_timeout[4:]
    samples.append(frag_reassembly_timeout)
    
    parameter_problem = bytes([
        12, 0,
        0, 0,
        0x08, 0x00,
        0, 0,
        0, 0, 0, 0,
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1,
        192, 168, 1, 2,
        0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01
    ])
    checksum = calculate_checksum(parameter_problem)
    parameter_problem = bytes([12, 0]) + struct.pack('>H', checksum) + parameter_problem[4:]
    samples.append(parameter_problem)
    
    timestamp_request = bytes([
        13, 0,
        0, 0,
        0x12, 0x34,
        0x00, 0x01,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    ])
    checksum = calculate_checksum(timestamp_request)
    timestamp_request = bytes([13, 0]) + struct.pack('>H', checksum) + timestamp_request[4:]
    samples.append(timestamp_request)
    
    timestamp_reply = bytes([
        14, 0,
        0, 0,
        0x12, 0x34,
        0x00, 0x01,
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C
    ])
    checksum = calculate_checksum(timestamp_reply)
    timestamp_reply = bytes([14, 0]) + struct.pack('>H', checksum) + timestamp_reply[4:]
    samples.append(timestamp_reply)
    
    info_request = bytes([
        15, 0,
        0, 0,
        0x12, 0x34,
        0x00, 0x01
    ])
    checksum = calculate_checksum(info_request)
    info_request = bytes([15, 0]) + struct.pack('>H', checksum) + info_request[4:]
    samples.append(info_request)
    
    info_reply = bytes([
        16, 0,
        0, 0,
        0x12, 0x34,
        0x00, 0x01
    ])
    checksum = calculate_checksum(info_reply)
    info_reply = bytes([16, 0]) + struct.pack('>H', checksum) + info_reply[4:]
    samples.append(info_reply)
    
    # ========== 人为制造校验和错误的报文（用于测试校验和验证功能）==========
    # 取前 3 个正确报文，篡改其校验和字段
    corrupted_count = 0
    for i in range(min(3, len(samples))):
        correct_packet = samples[i]
        # 篡改校验和字段（字节 2 和 3）
        corrupted = bytearray(correct_packet)
        # 将校验和字段改为 0xFFFF（错误值）
        corrupted[2] = 0xFF
        corrupted[3] = 0xFF
        samples.append(bytes(corrupted))
        corrupted_count += 1
    
    # 再制造一个：修改报文内容但不改校验和（模拟传输错误）
    if len(samples) >= 4:
        correct_packet = samples[3]
        corrupted = bytearray(correct_packet)
        # 修改数据部分的一个字节（不影响校验和字段）
        if len(corrupted) > 8:
            corrupted[8] = (corrupted[8] + 1) % 256  # 修改数据部分
        samples.append(bytes(corrupted))
        corrupted_count += 1
    
    print(f"[INFO] 测试样本生成完成：{len(samples) - corrupted_count} 个正确报文，{corrupted_count} 个校验和错误报文")
    
    return samples


def create_sample_pcap_file(output_path: str = "sample_icmp.pcap"):
    """创建示例pcap文件用于测试"""
    samples = create_sample_icmp_packets()
    
    import struct
    
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<IIIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535))
        
        for i, sample in enumerate(samples):
            ts_sec = 1234567890 + i
            ts_usec = i * 100000
            
            ethernet_header = struct.pack('!6s6sH', 
                b'\x00\x0c\x29\x12\x34\x56',
                b'\x00\x0c\x29\x65\x43\x21',
                0x0800
            )
            
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45, 0x00,
                20 + len(sample),
                0x1234, 0x0000,
                64, 1, 0xABCD,
                socket.inet_aton('192.168.1.1'),
                socket.inet_aton('192.168.1.2')
            )
            
            full_packet = ethernet_header + ip_header + sample
            
            pcap_record = struct.pack('<IIII',
                ts_sec, ts_usec,
                len(full_packet), len(full_packet)
            )
            
            f.write(pcap_record)
            f.write(full_packet)
    
    print(f"示例pcap文件已创建: {output_path}")
    return output_path
