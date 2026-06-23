"""
ICMP差错报文分析程序 - 核心解析模块
遵循RFC792协议标准
"""

from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any
from enum import IntEnum


class ICMPType(IntEnum):
    """ICMP报文类型枚举 (RFC792)"""
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14
    INFORMATION_REQUEST = 15
    INFORMATION_REPLY = 16


class DestinationUnreachableCode(IntEnum):
    """目的不可达子代码"""
    NETWORK_UNREACHABLE = 0      # 网络不可达
    HOST_UNREACHABLE = 1         # 主机不可达
    PROTOCOL_UNREACHABLE = 2     # 协议不可达
    PORT_UNREACHABLE = 3         # 端口不可达
    FRAGMENTATION_NEEDED = 4     # 需要分片但设置了DF位
    SOURCE_ROUTE_FAILED = 5      # 源路由失败


class TimeExceededCode(IntEnum):
    """超时子代码"""
    TTL_EXCEEDED = 0             # TTL超时
    FRAGMENT_REASSEMBLY = 1      # 分片重组超时


@dataclass
class ICMPHeader:
    """ICMP首部结构"""
    type: int           # 类型 (1字节)
    code: int           # 代码 (1字节)
    checksum: int       # 校验和 (2字节)
    identifier: int     # 标识符 (2字节)
    sequence: int       # 序列号 (2字节)
    

@dataclass
class IPHeader:
    """IP首部结构（用于差错报文回溯）"""
    version: int
    header_length: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    source_ip: str
    dest_ip: str


@dataclass
class ICMPPacket:
    """完整的ICMP报文数据结构"""
    header: ICMPHeader
    payload: bytes
    original_ip_header: Optional[IPHeader] = None
    original_data: bytes = b''
    raw_data: bytes = b''
    calculated_checksum: int = 0
    checksum_valid: bool = False
    description: str = ''
    

class ICMPAnalyzer:
    """ICMP报文分析器"""
    
    # ICMP类型描述映射
    TYPE_DESCRIPTIONS = {
        0: "Echo Reply (回显应答)",
        3: "Destination Unreachable (目的不可达)",
        4: "Source Quench (源站抑制)",
        5: "Redirect (重定向)",
        8: "Echo Request (回显请求)",
        11: "Time Exceeded (超时)",
        12: "Parameter Problem (参数问题)",
        13: "Timestamp Request (时间戳请求)",
        14: "Timestamp Reply (时间戳应答)",
        15: "Information Request (信息请求)",
        16: "Information Reply (信息应答)"
    }
    
    # 目的不可达代码描述
    UNREACHABLE_CODES = {
        0: "网络不可达 (Network Unreachable)",
        1: "主机不可达 (Host Unreachable)",
        2: "协议不可达 (Protocol Unreachable)",
        3: "端口不可达 (Port Unreachable)",
        4: "需要分片但DF位置位 (Fragmentation Needed and DF Set)",
        5: "源路由失败 (Source Route Failed)"
    }
    
    # 超时代码描述
    TIME_EXCEEDED_CODES = {
        0: "TTL超时 (Time to Live Exceeded)",
        1: "分片重组超时 (Fragment Reassembly Time Exceeded)"
    }
    
    def __init__(self):
        self.packet_count = 0
        self.type_stats: Dict[int, int] = {}
        self.error_count = 0
        self.checksum_error_count = 0
        
    def parse_icmp_header(self, data: bytes) -> Optional[ICMPHeader]:
        """解析ICMP首部"""
        if len(data) < 8:
            return None
            
        icmp_type = data[0]
        code = data[1]
        checksum = (data[2] << 8) + data[3]
        identifier = (data[4] << 8) + data[5]
        sequence = (data[6] << 8) + data[7]
        
        return ICMPHeader(
            type=icmp_type,
            code=code,
            checksum=checksum,
            identifier=identifier,
            sequence=sequence
        )
    
    def parse_ip_header(self, data: bytes) -> Optional[IPHeader]:
        """解析IP首部（用于差错报文中的原始IP首部回溯）"""
        if len(data) < 20:
            return None
            
        version = (data[0] >> 4) & 0x0F
        header_length = (data[0] & 0x0F) * 4
        tos = data[1]
        total_length = (data[2] << 8) + data[3]
        identification = (data[4] << 8) + data[5]
        flags = (data[6] >> 5) & 0x07
        fragment_offset = ((data[6] & 0x1F) << 8) + data[7]
        ttl = data[8]
        protocol = data[9]
        checksum = (data[10] << 8) + data[11]
        
        source_ip = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
        dest_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"
        
        return IPHeader(
            version=version,
            header_length=header_length,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            source_ip=source_ip,
            dest_ip=dest_ip
        )
    
    def calculate_checksum(self, data: bytes) -> int:
        """计算ICMP校验和 (RFC1071)"""
        if len(data) % 2 == 1:
            data = data + b'\x00'
            
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
            
        # 将进位加到低位
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            
        return ~checksum & 0xFFFF
    
    def verify_checksum(self, data: bytes, original_checksum: int) -> Tuple[int, bool]:
        """验证ICMP校验和"""
        # 方法1: 将校验和字段置0后重新计算
        # 创建校验和字段为0的数据副本
        data_with_zero_checksum = bytes([data[0], data[1], 0, 0]) + data[4:]
        calculated = self.calculate_checksum(data_with_zero_checksum)
        return calculated, (calculated == original_checksum)
    
    def analyze_echo(self, header: ICMPHeader) -> str:
        """分析Echo Request/Reply报文"""
        if header.type == ICMPType.ECHO_REQUEST:
            return f"Ping探测请求 - ID: {header.identifier}, 序列号: {header.sequence}"
        elif header.type == ICMPType.ECHO_REPLY:
            return f"Ping探测应答 - ID: {header.identifier}, 序列号: {header.sequence}"
        return ""
    
    def analyze_destination_unreachable(self, header: ICMPHeader, payload: bytes) -> str:
        """分析目的不可达报文"""
        code_desc = self.UNREACHABLE_CODES.get(header.code, f"未知代码 ({header.code})")
        
        # 解析原始IP首部（差错报文包含原始IP首部+前8字节数据）
        original_ip = None
        if len(payload) >= 28:  # 20字节IP首部 + 8字节数据
            original_ip = self.parse_ip_header(payload[:20])
            
        result = f"目的不可达: {code_desc}"
        if original_ip:
            result += f"\n  原始目标: {original_ip.dest_ip}"
            if original_ip.protocol == 6:
                result += " (TCP)"
            elif original_ip.protocol == 17:
                result += " (UDP)"
                
        return result
    
    def analyze_time_exceeded(self, header: ICMPHeader, payload: bytes) -> str:
        """分析超时报文"""
        code_desc = self.TIME_EXCEEDED_CODES.get(header.code, f"未知代码 ({header.code})")
        
        original_ip = None
        if len(payload) >= 28:
            original_ip = self.parse_ip_header(payload[:20])
            
        result = f"超时: {code_desc}"
        if original_ip:
            result += f"\n  原始源: {original_ip.source_ip} -> 目标: {original_ip.dest_ip}"
            result += f", TTL: {original_ip.ttl}"
                
        return result
    
    def is_query_message(self, icmp_type: int) -> bool:
        """判断是否为ICMP查询报文"""
        query_types = [
            ICMPType.ECHO_REQUEST,
            ICMPType.ECHO_REPLY,
            ICMPType.TIMESTAMP_REQUEST,
            ICMPType.TIMESTAMP_REPLY,
            ICMPType.INFORMATION_REQUEST,
            ICMPType.INFORMATION_REPLY
        ]
        return icmp_type in query_types
    
    def is_error_message(self, icmp_type: int) -> bool:
        """判断是否为ICMP差错报文"""
        error_types = [
            ICMPType.DESTINATION_UNREACHABLE,
            ICMPType.TIME_EXCEEDED,
            ICMPType.PARAMETER_PROBLEM,
            ICMPType.SOURCE_QUENCH,
            ICMPType.REDIRECT
        ]
        return icmp_type in error_types
    
    def analyze_packet(self, raw_data: bytes) -> Optional[ICMPPacket]:
        """完整分析ICMP报文"""
        header = self.parse_icmp_header(raw_data)
        if not header:
            return None
            
        # 获取载荷数据
        payload = raw_data[8:]
        
        # 计算并验证校验和
        calculated_checksum, checksum_valid = self.verify_checksum(raw_data, header.checksum)
        
        # 解析原始IP首部（差错报文）
        original_ip = None
        original_data = b''
        if self.is_error_message(header.type) and len(payload) >= 28:
            original_ip = self.parse_ip_header(payload[:20])
            original_data = payload[20:28]
        
        # 生成描述
        description = self._generate_description(header, payload)
        
        # 更新统计
        self.packet_count += 1
        self.type_stats[header.type] = self.type_stats.get(header.type, 0) + 1
        if not checksum_valid:
            self.checksum_error_count += 1
        
        if header.type in [ICMPType.DESTINATION_UNREACHABLE, ICMPType.SOURCE_QUENCH, 
                          ICMPType.REDIRECT, ICMPType.TIME_EXCEEDED, ICMPType.PARAMETER_PROBLEM]:
            self.error_count += 1
        
        return ICMPPacket(
            header=header,
            payload=payload,
            original_ip_header=original_ip,
            original_data=original_data,
            raw_data=raw_data,
            calculated_checksum=calculated_checksum,
            checksum_valid=checksum_valid,
            description=description
        )
    
    def _generate_description(self, header: ICMPHeader, payload: bytes) -> str:
        """生成报文描述"""
        type_desc = self.TYPE_DESCRIPTIONS.get(header.type, f"未知类型 ({header.type})")
        
        # 根据类型生成详细描述
        if header.type == ICMPType.ECHO_REQUEST or header.type == ICMPType.ECHO_REPLY:
            return self.analyze_echo(header)
        elif header.type == ICMPType.DESTINATION_UNREACHABLE:
            return self.analyze_destination_unreachable(header, payload)
        elif header.type == ICMPType.TIME_EXCEEDED:
            return self.analyze_time_exceeded(header, payload)
        else:
            return type_desc
    
    def format_output(self, packet: ICMPPacket) -> str:
        """格式化输出报文信息"""
        lines = []
        lines.append("=" * 60)
        lines.append("ICMP报文分析结果")
        lines.append("=" * 60)
        
        # 基本字段
        lines.append(f"类型 (Type): {packet.header.type} - {self.TYPE_DESCRIPTIONS.get(packet.header.type, '未知')}")
        lines.append(f"代码 (Code): {packet.header.code}")
        lines.append(f"校验和 (Checksum): 0x{packet.header.checksum:04X}")
        lines.append(f"计算校验和: 0x{packet.calculated_checksum:04X}")
        lines.append(f"校验和验证: {'[OK] 通过' if packet.checksum_valid else '[FAIL] 失败'}")
        
        # 标识符和序列号
        if packet.header.type in [ICMPType.ECHO_REQUEST, ICMPType.ECHO_REPLY, 
                                   ICMPType.TIMESTAMP_REQUEST, ICMPType.TIMESTAMP_REPLY]:
            lines.append(f"标识符 (Identifier): {packet.header.identifier}")
            lines.append(f"序列号 (Sequence): {packet.header.sequence}")
        
        # 报文分类
        if self.is_query_message(packet.header.type):
            lines.append("报文分类: 查询报文 (Query Message)")
        elif self.is_error_message(packet.header.type):
            lines.append("报文分类: 差错报文 (Error Message)")
        
        # 详细描述
        lines.append(f"\n详细描述:\n{packet.description}")
        
        # 原始IP首部（差错报文）
        if packet.original_ip_header:
            lines.append("\n原始IP首部回溯:")
            ip = packet.original_ip_header
            lines.append(f"  源IP: {ip.source_ip}")
            lines.append(f"  目的IP: {ip.dest_ip}")
            lines.append(f"  协议: {ip.protocol}")
            lines.append(f"  TTL: {ip.ttl}")
        
        # 载荷数据
        if packet.payload:
            lines.append(f"\n载荷数据长度: {len(packet.payload)} 字节")
            lines.append(f"载荷数据 (前64字节): {packet.payload[:64].hex()}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_packets': self.packet_count,
            'type_distribution': dict(self.type_stats),
            'error_packets': self.error_count,
            'checksum_errors': self.checksum_error_count,
            'type_percentages': {
                k: (v / self.packet_count * 100) if self.packet_count > 0 else 0 
                for k, v in self.type_stats.items()
            }
        }
