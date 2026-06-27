# ICMP差错报文分析程序
![Version](https://img.shields.io/badge/version-v2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## 项目简介
本程序是一个完整的ICMP差错报文分析工具，严格遵循RFC792协议标准，能够独立完成ICMP报文的二进制解析，区分查询报文与差错报文，还原ICMP协助IP协议差错报告、路径探测的底层工作逻辑。

## 更新日志

### v2.0.0 (2026-06-23)
- **重构**: UI全面升级，浅色主题，macOS风格界面
- **新增**: 顶部导航栏（控制/统计/工具/帮助/主题切换）
- **优化**: 三列布局支持拖拽调整宽度（控制面板18%/报文列表42%/详情面板40%）
- **优化**: 图表标题与内容间距调整，类型分布固定颜色映射
- **修复**: 统计信息与图表数据不一致问题（清空结果时重置分析器计数器）
- **修复**: 测试样本模式分析功能
- **优化**: 实时抓包和测试样本模式下文件浏览按钮禁用
- **优化**: 统计报告中类型号转换为类型名称显示

### v1.1.1 (2026-06-23)
- **优化**: 移除原生socket抓包方式，统一使用Scapy+Npcap实现
- **优化**: 超时时间改为最大抓包时间，0表示无限制
- **修复**: 统计面板有效报文计算逻辑错误
- **修复**: IP首部长度解析错误
- **新增**: 测试文档 TEST_DOCUMENT.md

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
基于Python+Scapy实现的ICMP报文二进制解析工具，严格遵循RFC 792协议标准，支持实时抓包、离线pcap文件解析和图形化分析面板。

## 功能特性

### ✅ 核心功能
- **ICMP报文读取**：支持实时网卡抓取、离线pcap文件、内置测试样本三种模式
- **Echo Request/Echo Reply分析**：解析Ping探测报文，核对标识符与序列号
- **Destination Unreachable分析**：细分网络不可达(0)、主机不可达(1)、协议不可达(2)、端口不可达(3)四类子代码
- **Time Exceeded分析**：区分TTL超时(0)与分片重组超时(1)两类场景
- **校验和验证**：独立实现RFC 1071反码求和算法，与原始校验和比对验证报文完整性
- **全字段解析输出**：展示Type、Code、Checksum、标识符、序列号、载荷数据、原始IP首部回溯

### 🎨 图形化界面
- 三栏布局：控制面板(18%)、报文列表(42%)、详情面板(40%)
- 支持搜索、过滤、排序功能
- 实时统计图表展示报文类型分布
- 十六进制原始数据查看

### 📊 统计分析
- 各类ICMP报文占比统计
- 校验和错误报文数量统计
- 生成统计报表（CSV/文本格式）

## 技术栈

- **Python** 3.8+
- **Scapy** - 网络报文捕获与解析
- **Npcap** - Windows网卡抓包驱动
- **Tkinter** - 图形化界面
- **python-docx** - 实验报告生成
- **matplotlib** - 统计图表

## 项目结构

```
jiwang/
├── main.py              # 主程序入口（CLI/GUI双模式）
├── gui.py               # 图形化界面模块
├── icmp_analyzer.py     # ICMP核心分析模块
├── packet_reader.py     # 报文读取模块（实时/离线/样本）
├── utils.py             # 公共工具模块（校验和计算）
├── generate_report.py   # 实验报告生成脚本
└── README.md            # 项目说明文档
```

## 快速开始

### 1. 安装依赖

```bash
pip install scapy python-docx matplotlib
```

### 2. 安装Npcap驱动

在Windows系统上，需要安装[Npcap](https://npcap.com/)驱动才能进行实时抓包。

### 3. 运行程序

```bash
# 默认启动图形界面
python main.py

# 命令行模式 - 使用测试样本
python main.py --sample

# 命令行模式 - 分析pcap文件
python main.py --file capture.pcap

# 命令行模式 - 实时抓包（需管理员权限）
python main.py --live --timeout 30 --count 100

# 启动图形界面
python main.py --gui

# 导出分析结果
python main.py --sample --output result.txt
```

## 使用说明

### 图形界面模式

1. **选择数据源**：
   - 离线文件模式：选择本地pcap文件
   - 实时抓包模式：选择网卡接口，设置超时时间和抓包数量
   - 测试样本模式：使用内置的20个RFC标准测试报文

2. **开始分析**：点击"开始分析"按钮

3. **查看结果**：
   - 左侧报文列表显示所有捕获的ICMP报文
   - 右侧详情面板展示选中报文的完整解析信息
   - 切换标签页查看字段解析、原始数据、统计信息

### 命令行模式

```bash
# 实时抓包参数
python main.py --live --interface Ethernet --timeout 60 --count 50

# 参数说明
--gui          # 启动图形界面
--sample       # 使用测试样本
--file PATH    # 分析pcap文件
--live         # 实时抓包模式
--interface    # 指定网卡接口（可选）
--timeout      # 抓包超时时间（秒），0表示无限制
--count        # 抓包数量，0表示无限制
--output       # 导出结果到文件
```

## 协议标准

- **RFC 792** - Internet Control Message Protocol
- **RFC 1071** - Computing the Internet Checksum
- **RFC 791** - Internet Protocol

## 测试结果

| 功能模块 | 测试样本数 | 通过数 | 通过率 |
|---------|-----------|-------|-------|
| Echo Request/Reply | 16 | 16 | 100% |
| Destination Unreachable | 4 | 4 | 100% |
| Time Exceeded | 7 | 7 | 100% |
| 校验和验证 | 66 | 66 | 100% |

## 生成实验报告

```bash
python generate_report.py
```

生成的报告文件：`ICMP差错报文分析实验报告.docx`

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request！