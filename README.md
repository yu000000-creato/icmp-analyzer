# ICMP差错报文分析程序

![Version](https://img.shields.io/badge/version-v1.1.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## 项目简介

本程序是一个完整的ICMP差错报文分析工具，严格遵循RFC792协议标准，能够独立完成ICMP报文的二进制解析，区分查询报文与差错报文，还原ICMP协助IP协议差错报告、路径探测的底层工作逻辑。

## 更新日志

### v1.1.0 (2026-06-23)
- **修复**: 统计面板正确区分ICMP差错报文与校验和错误报文
- **优化**: 离线文件模式添加文件验证（检查是否为目录、文件格式验证）
- **优化**: 使用标准tkinter.messagebox替代ttkbootstrap.dialogs.Messagebox确保弹窗正常显示
- **优化**: 实时抓包Npcap接口检测与服务状态检查

### v1.0.0 (2026-06-22)
- 实现ICMP报文全类型解析（Echo、Destination Unreachable、Time Exceeded等）
- 支持实时网卡抓包、离线pcap文件、二进制样本三种模式
- 图形化界面（tkinter + ttkbootstrap暗黑主题）
- 统计报表功能
- ICMP校验和验证

## 项目地址

- **GitHub**: https://github.com/yu000000-creato/icmp-analyzer

## 功能特性

### 核心功能
- **ICMP报文读取**: 支持实时网卡抓包、离线pcap文件、二进制样本
- **Echo Request/Reply分析**: 解析ping探测报文，核对标识符与序列号
- **Destination Unreachable分析**: 细分网络不可达、主机不可达、端口不可达、协议不可达4类子代码
- **Time Exceeded分析**: 区分TTL超时、分片重组超时两类场景
- **ICMP校验和验证**: 本地重新计算校验和并与原始值比对
- **全字段解析输出**: Type、Code、Checksum、标识符、序列号、载荷数据、原始IP首部回溯

### 扩展功能
- **离线pcap文件批量解析**: 兼容Wireshark导出报文
- **Tkinter图形化界面**: 分栏展示字段释义
- **统计报表**: 各类ICMP报文占比、异常报文数量统计

## 环境要求

### 系统要求
- **操作系统**: Windows 7/8/10/11 或 Linux/macOS
- **Python版本**: Python 3.7+

### 依赖包
```bash
# 基础功能（无需额外依赖）
# 仅使用Python标准库即可运行

# 可选依赖（用于增强功能）
pip install scapy>=2.5.0
```

**注意**: 
- 基本功能仅使用Python标准库，无需安装额外依赖
- 如需处理pcap文件或使用高级抓包功能，建议安装scapy
- 实时抓包需要管理员权限

## 安装步骤

### 1. 克隆或下载项目
```bash
cd C:\Users\13064\Desktop\jiwang
```

### 2. 安装可选依赖（推荐）
```bash
pip install scapy
```

### 3. 验证安装
```bash
python test_icmp.py
```

如果看到 `[PASS] 所有测试通过!`，说明安装成功。

## 使用方法

### 方式一：图形界面模式（推荐）

#### 启动图形界面
```bash
python main.py --gui
```

#### 图形界面操作

**1. 测试样本模式（最简单）**
- 选择 "测试样本" 单选按钮
- 直接点击 "开始分析"
- 查看解析结果和统计信息

**2. 离线文件分析**
- 选择 "离线文件" 单选按钮
- 点击 "浏览..." 选择pcap文件
  - 项目已提供示例文件：`sample_icmp.pcap`
  - 也可使用Wireshark抓包导出的pcap文件
- 点击 "开始分析"
- 在左侧列表选择报文，右侧查看详细信息

**3. 实时抓包（需要管理员权限）**
- 选择 "实时抓包" 单选按钮
- 从下拉菜单选择网卡接口：
  - Windows: 以太网、WLAN等
  - Linux: eth0、wlan0等
- 设置抓包参数：
  - 抓包数量：0表示无限制，或填具体数字（如100）
  - 超时时间：抓包持续时间（秒）
- 点击 "开始分析"
- **重要**: 必须以管理员身份运行程序

**4. 其他功能**
- **清空结果**: 清除当前所有解析结果
- **生成报表**: 查看各类ICMP报文占比统计
- **导出结果**: 将分析结果保存到文本文件

---

### 方式二：命令行模式

#### 基本语法
```bash
python main.py [选项]
```

#### 常用命令

**1. 使用测试样本分析**
```bash
python main.py --sample
```

**2. 分析pcap文件**
```bash
python main.py --file sample_icmp.pcap
python main.py --file capture.pcap --output result.txt
```

**3. 实时抓包（需要管理员权限）**
```bash
# 基本抓包
python main.py --live

# 设置参数
python main.py --live --timeout 30 --count 100

# 指定网卡接口
python main.py --live --interface 以太网 --timeout 60
```

**4. 查看帮助**
```bash
python main.py --help
```

---

## 详细使用说明

### 实时抓包详细步骤

#### Windows系统
1. **以管理员身份运行命令提示符**
   - 右键点击"命令提示符"
   - 选择"以管理员身份运行"

2. **启动程序**
   ```bash
   cd C:\Users\13064\Desktop\jiwang
   python main.py --gui
   ```

3. **配置抓包参数**
   - 选择 "实时抓包" 模式
   - 选择网卡接口（推荐"以太网"或"WLAN"）
   - 设置超时时间（建议30-60秒）
   - 设置抓包数量（0为无限制）

4. **开始抓包**
   - 点击 "开始分析"
   - 程序会实时捕获ICMP报文
   - 可以随时点击 "停止" 终止抓包

5. **查看结果**
   - 左侧列表显示所有捕获的报文
   - 点击报文查看详细信息
   - 切换标签页查看字段解析、原始数据、统计信息

#### Linux系统
1. **使用sudo运行**
   ```bash
   sudo python main.py --gui
   ```

2. **选择网卡接口**
   - 常见接口：eth0、wlan0、ens33等
   - 使用 `ip addr` 或 `ifconfig` 查看可用接口

3. **其他步骤与Windows相同**

---

### 离线文件分析详细步骤

#### 1. 准备pcap文件
- **使用项目示例文件**: `sample_icmp.pcap`
- **使用Wireshark抓包**:
  1. 打开Wireshark
  2. 选择网卡开始抓包
  3. 设置过滤器：`icmp`
  4. 停止抓包并保存为pcap格式

#### 2. 在图形界面中分析
1. 选择 "离线文件" 模式
2. 点击 "浏览..." 选择pcap文件
3. 点击 "开始分析"
4. 查看解析结果

#### 3. 在命令行中分析
```bash
# 基本分析
python main.py --file capture.pcap

# 导出结果
python main.py --file capture.pcap --output analysis.txt
```

---

### 测试样本使用

测试样本包含4个ICMP报文：
1. **Echo Request** - Ping探测请求
2. **Echo Reply** - Ping探测应答
3. **Destination Unreachable** - 端口不可达
4. **Time Exceeded** - TTL超时

**使用方法**：
- 图形界面：选择"测试样本"模式，点击"开始分析"
- 命令行：`python main.py --sample`

---

## 输出说明

### 报文分析结果
```
============================================================
ICMP报文分析结果
============================================================
类型 (Type): 8 - Echo Request (回显请求)
代码 (Code): 0
校验和 (Checksum): 0x5435
计算校验和: 0x5435
校验和验证: [OK] 通过
标识符 (Identifier): 4660
序列号 (Sequence): 1
报文分类: 查询报文 (Query Message)

详细描述:
Ping探测请求 - ID: 4660, 序列号: 1

载荷数据长度: 8 字节
载荷数据 (前64字节): 6162636465666768
============================================================
```

### 统计报表
```
============================================================
统计信息
============================================================
总报文数: 4
校验和错误报文数: 0

报文类型分布:
  Type  0 (Echo Reply (回显应答)):    1 ( 25.0%)
  Type  3 (Destination Unreacha):    1 ( 25.0%)
  Type  8 (Echo Request (回显请求)):    1 ( 25.0%)
  Type 11 (Time Exceeded (超时)):    1 ( 25.0%)
```

---

## 常见问题解决

### 1. 实时抓包提示"需要管理员权限"
**解决方案**：
- Windows: 右键命令提示符，选择"以管理员身份运行"
- Linux: 使用 `sudo python main.py --gui`

### 2. 网卡接口列表为空
**解决方案**：
- 安装scapy: `pip install scapy`
- 或使用测试样本模式进行测试

### 3. 离线文件解析失败
**可能原因**：
- 文件格式不正确（必须是pcap格式）
- 文件中没有ICMP报文
- 文件损坏

**解决方案**：
- 使用项目提供的 `sample_icmp.pcap` 测试
- 确保文件是标准的pcap格式
- 使用Wireshark打开文件验证

### 4. 校验和验证失败
**可能原因**：
- 报文在传输过程中被修改
- 报文格式不正确
- 程序bug

**解决方案**：
- 使用测试样本验证程序功能
- 检查报文来源是否可靠

### 5. 图形界面无法启动
**可能原因**：
- Tkinter未安装（Python 3.7+默认包含）
- 显示问题

**解决方案**：
- 使用命令行模式：`python main.py --sample`
- 检查Python版本：`python --version`

---

## 项目文件说明

```
jiwang/
├── icmp_analyzer.py      # 核心ICMP解析模块
├── packet_reader.py      # 报文读取模块
├── gui.py                # Tkinter图形化界面
├── main.py               # 主程序入口
├── test_icmp.py          # 测试脚本
├── requirements.txt      # 依赖文件
├── sample_icmp.pcap      # 示例pcap文件
└── README.md             # 本文档
```

---

## 技术特性

### 协议标准
- 严格遵循 **RFC792** 协议标准
- 支持 **RFC1071** 校验和计算算法

### ICMP类型支持
- **查询报文**: Echo Request/Reply, Timestamp Request/Reply, Information Request/Reply
- **差错报文**: Destination Unreachable, Time Exceeded, Parameter Problem, Source Quench, Redirect

### 差错报文子代码
- **Destination Unreachable**: 网络不可达、主机不可达、协议不可达、端口不可达
- **Time Exceeded**: TTL超时、分片重组超时

---

## 测试方法

### 运行测试脚本
```bash
python test_icmp.py
```

### 测试内容
1. 核心分析功能测试
2. 报文读取功能测试
3. 校验和计算测试

### 预期结果
```
[PASS] 所有测试通过! 程序功能正常。
```

---

## 性能说明

- **内存占用**: 约50-100MB（取决于报文数量）
- **CPU占用**: 实时抓包时约5-15%
- **处理速度**: 约1000-5000报文/秒

---

## 安全说明

- 实时抓包需要管理员权限
- 仅分析ICMP协议，不修改网络数据
- 不会对网络造成任何影响

---

## 开发者信息

本项目为ICMP差错报文分析实验项目，遵循RFC792协议标准开发。

---

## 更新日志

### v1.0.0 (2025-06-17)
- 完成核心ICMP解析功能
- 实现实时抓包和离线文件读取
- 添加图形化界面
- 完善统计报表功能
- 通过完整功能测试

---

## 联系方式

如有问题或建议，请通过以下方式联系：
- 项目路径: `c:\Users\13064\Desktop\jiwang`
- 测试命令: `python test_icmp.py`