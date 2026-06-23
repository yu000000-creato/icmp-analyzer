# ICMP差错报文分析程序 - 测试文档

**版本**: v2.0.0  
**日期**: 2026-06-23  
**协议标准**: RFC792  
**环境**: Windows + Python 3.x + Npcap  

---

## 目录

1. [测试概述](#1-测试概述)
2. [测试环境](#2-测试环境)
3. [功能测试用例](#3-功能测试用例)
   - 3.1 [ICMP报文读取测试](#31-icmp报文读取测试)
   - 3.2 [Echo Request/Echo Reply分析测试](#32-echo-requestechoreply分析测试)
   - 3.3 [Destination Unreachable分析测试](#33-destination-unreachable分析测试)
   - 3.4 [Time Exceeded超时分析测试](#34-time-exceeded超时分析测试)
   - 3.5 [ICMP校验和验证测试](#35-icmp校验和验证测试)
   - 3.6 [全字段解析输出测试](#36-全字段解析输出测试)
   - 3.7 [pcap文件批量解析测试](#37-pcap文件批量解析测试)
   - 3.8 [图形化界面测试](#38-图形化界面测试)
   - 3.9 [报文统计与流量报表测试](#39-报文统计与流量报表测试)
4. [边界测试用例](#4-边界测试用例)
5. [性能测试用例](#5-性能测试用例)
6. [测试结果汇总](#6-测试结果汇总)

---

## 1. 测试概述

### 1.1 测试目的

验证ICMP差错报文分析程序的所有功能是否正确实现，严格遵循RFC792协议标准。

### 1.2 测试范围

| 模块 | 测试内容 |
|------|---------|
| `icmp_analyzer.py` | ICMP报文解析、校验和计算、类型分类、字段提取 |
| `packet_reader.py` | 实时抓包、pcap文件读取、二进制样本读取 |
| `main.py` | CLI命令行接口、参数解析、结果导出 |
| `gui.py` | 图形化界面、三栏布局、统计报表 |

### 1.3 测试方法

- **黑盒测试**: 验证功能输入输出是否符合预期
- **白盒测试**: 验证关键算法（校验和计算、协议解析）正确性
- **自动化测试**: 使用内置测试样本进行快速验证
- **手动测试**: 实际抓包场景验证

---

## 2. 测试环境

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10/11 |
| Python版本 | 3.8+ |
| 依赖库 | scapy, ttkbootstrap, tkinter |
| 网络驱动 | Npcap 1.88+ |
| 权限要求 | 实时抓包需管理员权限 |

### 2.1 环境准备

```bash
# 安装依赖
pip install scapy ttkbootstrap

# 验证Npcap安装
python check_npcap.py

# 创建测试样本
python -c "from packet_reader import create_sample_pcap_file; create_sample_pcap_file()"
```

---

## 3. 功能测试用例

### 3.1 ICMP报文读取测试

#### 3.1.1 实时网卡抓包

**测试编号**: TC-READ-001  
**测试目的**: 验证实时网卡抓包功能  
**测试步骤**:

1. 以管理员身份运行命令：
   ```bash
   python main.py --live --count 5
   ```

2. 在另一终端执行ping命令：
   ```bash
   ping 127.0.0.1 -n 3
   ```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 程序启动 | 显示"开始实时抓包"提示 |
| 捕获数量 | 至少捕获3个Echo Request + 3个Echo Reply |
| 报文类型 | Type=8 (Echo Request) 和 Type=0 (Echo Reply) |
| 错误处理 | 非管理员权限时显示权限错误提示 |

---

#### 3.1.2 无限制抓包

**测试编号**: TC-READ-002  
**测试目的**: 验证timeout=0时无限制抓包  
**测试步骤**:

```bash
python main.py --live --timeout 0 --interface 回环接口
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 启动提示 | "最大抓包时间: 无限制" |
| 抓包行为 | 持续抓包直到Ctrl+C中断 |
| 中断处理 | Ctrl+C后正常退出，显示统计信息 |

---

#### 3.1.3 二进制样本读取

**测试编号**: TC-READ-003  
**测试目的**: 验证内置测试样本解析  
**测试步骤**:

```bash
python main.py --sample
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 报文数量 | 4个 |
| 报文1 | Type=8, Echo Request |
| 报文2 | Type=0, Echo Reply |
| 报文3 | Type=3, Destination Unreachable (Code=3) |
| 报文4 | Type=11, Time Exceeded (Code=0) |

---

### 3.2 Echo Request/Echo Reply分析测试

**测试编号**: TC-ECHO-001  
**测试目的**: 验证Ping探测报文解析  
**测试步骤**:

```bash
python main.py --sample
```

**预期结果**:

| 报文 | Type | Code | Identifier | Sequence | 分类 |
|------|------|------|------------|----------|------|
| #1 | 8 | 0 | 4660 (0x1234) | 1 | 查询报文 |
| #2 | 0 | 0 | 4660 (0x1234) | 1 | 查询报文 |

**详细描述验证**:
- 报文#1: `Ping探测请求 - ID: 4660, 序列号: 1`
- 报文#2: `Ping探测应答 - ID: 4660, 序列号: 1`

---

### 3.3 Destination Unreachable分析测试

**测试编号**: TC-DEST-001  
**测试目的**: 验证目的不可达报文细分解析  
**测试步骤**:

```bash
python main.py --sample
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| Type | 3 |
| Code | 3 |
| 描述 | `目的不可达: 端口不可达 (Port Unreachable)` |
| 原始目标 | `192.168.1.2 (TCP)` |
| 报文分类 | 差错报文 |

**原始IP首部回溯验证**:

| 字段 | 预期值 |
|------|--------|
| 源IP | 192.168.1.1 |
| 目的IP | 192.168.1.2 |
| 协议 | 6 (TCP) |
| TTL | 64 |

---

#### 3.3.2 手动构造目的不可达

**测试编号**: TC-DEST-002  
**测试目的**: 验证真实网络环境下的目的不可达报文  
**测试步骤**:

1. 启动抓包：
   ```bash
   python main.py --live --interface 回环接口 --count 1
   ```

2. 在另一终端发送UDP到未开放端口：
   ```bash
   python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'test', ('127.0.0.1', 9999))"
   ```

**预期结果**: 捕获Type=3, Code=3（端口不可达）报文

---

### 3.4 Time Exceeded超时分析测试

**测试编号**: TC-TIME-001  
**测试目的**: 验证超时报文解析  
**测试步骤**:

```bash
python main.py --sample
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| Type | 11 |
| Code | 0 |
| 描述 | `超时: TTL超时 (Time to Live Exceeded)` |
| 报文分类 | 差错报文 |

**原始IP首部回溯验证**:

| 字段 | 预期值 |
|------|--------|
| 源IP | 10.0.0.1 |
| 目的IP | 10.0.0.2 |
| 协议 | 6 (TCP) |
| TTL | 1 |

---

#### 3.4.2 手动构造TTL超时

**测试编号**: TC-TIME-002  
**测试目的**: 验证真实网络环境下的TTL超时  
**测试步骤**:

1. 启动抓包：
   ```bash
   python main.py --live --interface 以太网 --count 2
   ```

2. 在另一终端执行traceroute：
   ```bash
   tracert -d -h 1 www.baidu.com
   ```

**预期结果**: 捕获Type=11, Code=0（TTL超时）报文

---

### 3.5 ICMP校验和验证测试

**测试编号**: TC-CHKSUM-001  
**测试目的**: 验证校验和计算与验证功能  
**测试步骤**:

```bash
python main.py --sample
```

**预期结果**:

| 报文 | 原始校验和 | 计算校验和 | 验证结果 |
|------|-----------|-----------|---------|
| #1 | 0x5435 | 0x5435 | [OK] 通过 |
| #2 | 0x5C35 | 0x5C35 | [OK] 通过 |
| #3 | 0xF3D7 | 0xF3D7 | [OK] 通过 |
| #4 | 0x9A2C | 0x9A2C | [OK] 通过 |

---

#### 3.5.2 校验和错误测试

**测试编号**: TC-CHKSUM-002  
**测试目的**: 验证校验和错误检测  
**测试步骤**:

```bash
python -c "
from icmp_analyzer import ICMPAnalyzer

# 构造校验和错误的报文
corrupted = bytes([8, 0, 0xFF, 0xFF, 0x12, 0x34, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64])

analyzer = ICMPAnalyzer()
result = analyzer.analyze_packet(corrupted)

print(f'原始校验和: 0x{result.header.checksum:04X}')
print(f'计算校验和: 0x{result.calculated_checksum:04X}')
print(f'验证结果: {result.checksum_valid}')
print(f'校验和错误计数: {analyzer.checksum_error_count}')
"
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 原始校验和 | 0xFFFF |
| 计算校验和 | 0xXXXX（与原始不同） |
| 验证结果 | False |
| 错误计数 | 1 |

---

### 3.6 全字段解析输出测试

**测试编号**: TC-FIELDS-001  
**测试目的**: 验证所有字段正确解析和输出  
**测试步骤**:

```bash
python main.py --sample
```

**预期输出格式**:

```
============================================================
ICMP报文分析结果
============================================================
类型 (Type): 3 - Destination Unreachable (目的不可达)
代码 (Code): 3
校验和 (Checksum): 0xF3D7
计算校验和: 0xF3D7
校验和验证: [OK] 通过
报文分类: 差错报文 (Error Message)

详细描述:
目的不可达: 端口不可达 (Port Unreachable)
  原始目标: 192.168.1.2 (TCP)

原始IP首部回溯:
  源IP: 192.168.1.1
  目的IP: 192.168.1.2
  协议: 6
  TTL: 64

载荷数据长度: 28 字节
载荷数据 (前64字节): 450000280001000040060000c0a80101c0a801020050005000000001
============================================================
```

**字段验证表**:

| 字段 | 说明 | 是否输出 |
|------|------|---------|
| Type | 类型编号 + 描述 | ✅ |
| Code | 子代码编号 | ✅ |
| Checksum | 原始校验和(十六进制) | ✅ |
| Calculated Checksum | 计算校验和(十六进制) | ✅ |
| Checksum Valid | 验证结果 | ✅ |
| Identifier | 查询报文标识符 | ✅ (仅查询报文) |
| Sequence | 查询报文序列号 | ✅ (仅查询报文) |
| Classification | 查询/差错报文分类 | ✅ |
| Description | 详细描述 | ✅ |
| Original IP Header | 差错报文原始IP首部 | ✅ (仅差错报文) |
| Payload | 载荷数据长度 + 十六进制 | ✅ |

---

### 3.7 pcap文件批量解析测试

**测试编号**: TC-PCAP-001  
**测试目的**: 验证pcap文件解析功能  
**测试步骤**:

```bash
# 使用内置生成的样本pcap
python main.py --file sample_icmp.pcap

# 使用Wireshark导出的pcap文件
python main.py --file your_capture.pcap
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 文件读取 | 成功打开pcap文件 |
| 报文提取 | 正确提取所有ICMP报文 |
| 格式兼容 | 支持little-endian和big-endian格式 |
| 解析结果 | 与实时抓包一致 |

---

### 3.8 图形化界面测试

**测试编号**: TC-GUI-001  
**测试目的**: 验证GUI启动和布局  
**测试步骤**:

```bash
python main.py --gui
# 或直接运行
python main.py
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 窗口启动 | 正常显示，无报错 |
| 窗口比例 | 16:10固定比例 |
| 三栏布局 | 控制面板(18%) | 报文列表(42%) | 详情面板(40%) |
| 主题颜色 | 深色主题，配色符合规范 |

---

#### 3.8.2 GUI功能测试

**测试编号**: TC-GUI-002  
**测试目的**: 验证GUI各功能模块  
**测试步骤**:

1. **模式切换测试**:
   - 点击"实时抓包"模式 → 检查接口选择、超时、数量参数显示
   - 点击"离线文件"模式 → 检查文件选择按钮显示
   - 点击"测试样本"模式 → 确认切换成功

2. **实时抓包测试**:
   - 选择接口 → 点击"开始分析" → 检查状态栏显示"正在分析"
   - 发送ping → 检查报文列表更新
   - 点击"停止" → 检查状态栏显示"已停止"

3. **离线分析测试**:
   - 选择pcap文件 → 点击"开始分析" → 检查报文列表更新

4. **详情查看测试**:
   - 点击报文列表中的条目 → 检查详情面板显示完整字段

5. **统计面板测试**:
   - 分析报文后 → 检查右侧统计面板显示正确数据

6. **报表生成测试**:
   - 点击"生成报表"按钮 → 检查报表弹窗显示

7. **导出功能测试**:
   - 点击"导出结果"按钮 → 选择路径 → 检查文件生成

8. **清空功能测试**:
   - 点击"清空"按钮 → 检查所有面板清空

**预期结果**: 所有功能按钮工作正常，无异常报错

---

### 3.9 报文统计与流量报表测试

**测试编号**: TC-STATS-001  
**测试目的**: 验证统计功能  
**测试步骤**:

```bash
python main.py --sample
```

**预期统计输出**:

```
============================================================
统计信息
============================================================
总报文数: 4
校验和错误报文数: 0

报文类型分布:
  Type  0 (Echo Reply (回显应):    1 ( 25.0%)
  Type  3 (Destination Unreacha):    1 ( 25.0%)
  Type  8 (Echo Request (回显请):    1 ( 25.0%)
  Type 11 (Time Exceeded (超时)):    1 ( 25.0%)
```

**统计项验证**:

| 统计项 | 预期值 |
|--------|--------|
| 总报文数 | 4 |
| 校验和错误 | 0 |
| Type分布 | 各类型1个，占比25% |
| 差错报文数 | 2 (Type 3 + Type 11) |

---

#### 3.9.2 结果导出测试

**测试编号**: TC-STATS-002  
**测试目的**: 验证结果导出功能  
**测试步骤**:

```bash
python main.py --sample --output test_result.txt
```

**预期结果**:

| 检查项 | 预期值 |
|--------|--------|
| 文件生成 | `test_result.txt` 创建成功 |
| 文件内容 | 包含所有报文分析结果 |
| 文件编码 | UTF-8 |

---

## 4. 边界测试用例

### 4.1 异常数据测试

**测试编号**: TC-BOUND-001  
**测试目的**: 验证异常数据处理  
**测试步骤**:

```bash
python -c "
from icmp_analyzer import ICMPAnalyzer

analyzer = ICMPAnalyzer()

# 测试1: 空数据
result = analyzer.analyze_packet(b'')
print(f'空数据: {result}')  # 预期: None

# 测试2: 不完整报文(少于8字节)
result = analyzer.analyze_packet(b'\x08\x00\x00\x00')
print(f'不完整报文: {result}')  # 预期: None

# 测试3: 无效类型
invalid_packet = bytes([0xFF, 0, 0, 0, 0, 0, 0, 0])
result = analyzer.analyze_packet(invalid_packet)
print(f'无效类型: {result.header.type}')  # 预期: 255

# 测试4: 超长载荷
long_payload = bytes([8, 0, 0, 0, 1, 2, 3, 4]) + b'x' * 1000
result = analyzer.analyze_packet(long_payload)
print(f'超长载荷长度: {len(result.payload)}')  # 预期: 1000
"
```

**预期结果**: 程序正常处理，不崩溃，正确返回None或解析结果

---

### 4.2 参数边界测试

**测试编号**: TC-BOUND-002  
**测试目的**: 验证参数边界值  
**测试步骤**:

```bash
# 测试timeout边界
python main.py --live --timeout -1 --count 1   # 预期: 提示无效，使用默认值
python main.py --live --timeout 0 --count 1    # 预期: 无限制
python main.py --live --timeout 99999 --count 1 # 预期: 正常处理

# 测试count边界
python main.py --live --count -1               # 预期: 使用默认值0
python main.py --live --count 0                # 预期: 无限制
python main.py --live --count 1                # 预期: 捕获1个后停止
```

---

### 4.3 特殊场景测试

**测试编号**: TC-BOUND-003  
**测试目的**: 验证特殊网络场景  
**测试步骤**:

1. **无网络连接**:
   ```bash
   python main.py --live --timeout 5
   ```
   预期: 无报文捕获，正常超时退出

2. **高流量场景**:
   ```bash
   # 持续ping产生大量报文
   ping -t 127.0.0.1
   python main.py --live --interface 回环接口 --count 100 --timeout 0
   ```
   预期: 正确处理100个报文，无丢包

---

## 5. 性能测试用例

### 5.1 解析速度测试

**测试编号**: TC-PERF-001  
**测试目的**: 验证报文解析速度  
**测试步骤**:

```bash
python -c "
import time
from icmp_analyzer import ICMPAnalyzer
from packet_reader import create_sample_icmp_packets

samples = create_sample_icmp_packets()
analyzer = ICMPAnalyzer()

# 测试10000次解析
start = time.time()
for _ in range(10000):
    for data in samples:
        analyzer.analyze_packet(data)
end = time.time()

print(f'解析10000次耗时: {end - start:.2f}秒')
print(f'平均解析速度: {40000 / (end - start):.0f} 报文/秒')
"
```

**预期结果**: 解析速度 ≥ 10000 报文/秒

---

### 5.2 pcap文件解析性能

**测试编号**: TC-PERF-002  
**测试目的**: 验证大文件解析性能  
**测试步骤**:

```bash
# 使用较大的pcap文件测试
python main.py --file large_capture.pcap --output result.txt
```

**预期结果**: 无内存溢出，解析完成时间合理

---

## 6. 测试结果汇总

### 6.1 测试用例统计

| 模块 | 测试用例数 | 通过 | 失败 | 跳过 |
|------|-----------|------|------|------|
| ICMP报文读取 | 3 | | | |
| Echo Request/Reply分析 | 1 | | | |
| Destination Unreachable分析 | 2 | | | |
| Time Exceeded分析 | 2 | | | |
| 校验和验证 | 2 | | | |
| 全字段解析输出 | 1 | | | |
| pcap文件解析 | 1 | | | |
| 图形化界面 | 2 | | | |
| 统计与报表 | 2 | | | |
| 边界测试 | 3 | | | |
| 性能测试 | 2 | | | |
| **总计** | **21** | | | |

### 6.2 测试执行记录

| 测试日期 | 测试人 | 环境 | 结果 |
|---------|--------|------|------|
| | | | |

### 6.3 已知问题

| 问题描述 | 影响范围 | 严重程度 | 状态 |
|---------|---------|---------|------|
| | | | |

---

## 附录：测试命令速查

```bash
# 快速验证所有核心功能
python main.py --sample

# 实时抓包（需管理员权限）
python main.py --live --count 5

# 分析pcap文件
python main.py --file sample_icmp.pcap

# 启动图形界面
python main.py --gui

# 生成测试样本pcap
python -c "from packet_reader import create_sample_pcap_file; create_sample_pcap_file()"

# 检查Npcap安装
python check_npcap.py
```

---

**文档版本**: v2.0.0  
**最后更新**: 2026-06-23