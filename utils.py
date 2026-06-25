"""
ICMP差错报文分析程序 - 公共工具模块
"""

from typing import Optional, Tuple


def calculate_checksum(data: bytes) -> int:
    """计算校验和 (RFC1071)"""
    if len(data) % 2 == 1:
        data = data + b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF


def verify_checksum(data: bytes, original_checksum: int) -> Tuple[int, bool]:
    """验证校验和"""
    data_with_zero_checksum = bytes([data[0], data[1], 0, 0]) + data[4:]
    calculated = calculate_checksum(data_with_zero_checksum)
    return calculated, (calculated == original_checksum)


def format_ip_address(data: bytes, offset: int = 0) -> Optional[str]:
    """从字节数据中解析IP地址"""
    if len(data) < offset + 4:
        return None
    return f"{data[offset]}.{data[offset+1]}.{data[offset+2]}.{data[offset+3]}"


def format_hex(data: bytes, max_length: int = 64) -> str:
    """格式化十六进制数据"""
    hex_str = data.hex()
    if len(hex_str) > max_length * 2:
        hex_str = hex_str[:max_length * 2] + "..."
    return hex_str


def format_binary(data: bytes, max_length: int = 32) -> str:
    """格式化为二进制字符串"""
    if len(data) > max_length:
        data = data[:max_length]
    return ' '.join(f'{byte:08b}' for byte in data)


def bytes_to_int(data: bytes, big_endian: bool = True) -> int:
    """字节转整数"""
    if big_endian:
        return int.from_bytes(data, 'big')
    return int.from_bytes(data, 'little')


def decode_protocol(protocol: int) -> str:
    """解析协议号"""
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        89: 'OSPF'
    }
    return protocols.get(protocol, f"未知 ({protocol})")
