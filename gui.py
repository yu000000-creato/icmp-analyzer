"""
ICMP差错报文分析程序 v2.0 - 现代化网络抓包工具UI
浅色主题，支持macOS风格界面
"""

import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
from typing import Optional, List, Dict, Any
import threading
import queue
import time
from pathlib import Path
import ctypes

import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from icmp_analyzer import ICMPAnalyzer, ICMPPacket, ICMPType
from packet_reader import (
    LivePacketReader, OfflinePacketReader, BinarySampleReader,
    create_sample_icmp_packets, get_network_interfaces
)

# ========== 全局配色方案（浅色主题） ==========
COLORS = {
    'bg_main': '#f5f6f7',
    'bg_card': '#ffffff',
    'bg_highlight': '#f0f4f8',
    'accent_blue': '#4a90e2',
    'accent_hover': '#3a7bc8',
    'accent_light': '#e3f0fd',
    'accent_orange': '#ff9500',
    'accent_green': '#27ae60',
    'accent_red': '#e74c3c',
    'accent_yellow': '#f39c12',
    'text_primary': '#2c3e50',
    'text_secondary': '#6c7a89',
    'text_disabled': '#bdc3c7',
    'border': '#d1d8e0',
    'hover': '#eef2f7',
    'error_bg': '#fde8e8',
    'warning_bg': '#fef3e8',
    'success_bg': '#e8f8f0',
    'mac_red': '#ff5f57',
    'mac_yellow': '#ffbd2e',
    'mac_green': '#28c840',
}

# ========== 字体配置 ==========
FONTS = {
    'title': ('Microsoft YaHei', 18, 'bold'),
    'subtitle': ('Microsoft YaHei', 15),
    'label': ('Microsoft YaHei', 14),
    'label_bold': ('Microsoft YaHei', 14, 'bold'),
    'small': ('Microsoft YaHei', 15),
    'tiny': ('Microsoft YaHei', 15),
    'mono': ('Consolas', 15),
    'mono_small': ('Consolas', 15),
}


class ICMPAnalyzerGUI:
    """ICMP分析器图形界面 v2.0"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ICMP 差错报文分析 v2.0")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)
        self.root.configure(bg=COLORS['bg_main'])
        
        style = ttk.Style()
        style.configure('TCombobox', font=('Microsoft YaHei', 14))
        
        self.analyzer = ICMPAnalyzer()
        self.packet_queue = queue.Queue()
        self.capture_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        self.capture_start_time = 0
        self.packets: List[ICMPPacket] = []
        
        self.sort_column = '序号'
        self.sort_order = 'asc'
        
        self.tooltip = None
        self.tooltip_id = None
        
        self._create_widgets()
        
        self._bind_shortcuts()
        
    def _bind_shortcuts(self):
        """绑定快捷键"""
        self.root.bind('<Control-s>', lambda e: self._start_analysis())
        self.root.bind('<Control-S>', lambda e: self._start_analysis())
        self.root.bind('<Control-p>', lambda e: self._stop_capture())
        self.root.bind('<Control-P>', lambda e: self._stop_capture())
        self.root.bind('<Control-c>', lambda e: self._clear_results())
        self.root.bind('<Control-C>', lambda e: self._clear_results())
        self.root.bind('<Control-e>', lambda e: self._export_results())
        self.root.bind('<Control-E>', lambda e: self._export_results())
        self.root.bind('<Escape>', lambda e: self.root.quit())
        
    def _create_widgets(self):
        """创建界面组件"""
        # 主容器
        main_container = tk.Frame(self.root, bg=COLORS['bg_main'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # 顶部标题栏
        self._create_header(main_container)
        
        # 主体内容区
        body = tk.Frame(main_container, bg=COLORS['bg_main'])
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(8, 16))
        
        # 左右分割面板
        paned = ttk.PanedWindow(body, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # 左侧控制面板
        left_panel = tk.Frame(paned, bg=COLORS['bg_card'], width=440)
        left_panel.pack_propagate(False)  # 固定宽度，不随内容变化
        paned.add(left_panel, weight=0)
        
        # 右侧主显示区
        right_panel = tk.Frame(paned, bg=COLORS['bg_main'])
        paned.add(right_panel, weight=1)
        
        self._create_left_panel(left_panel)
        self._create_right_panel(right_panel)
        
    def _create_header(self, parent):
        """创建顶部标题栏"""
        header = tk.Frame(parent, bg=COLORS['bg_main'], height=48)
        header.pack(fill=tk.X, padx=16, pady=(12, 0))
        header.pack_propagate(False)
        
        # macOS风格窗口按钮
        btn_frame = tk.Frame(header, bg=COLORS['bg_main'])
        btn_frame.pack(side=tk.LEFT)
        
        for color in [COLORS['mac_red'], COLORS['mac_yellow'], COLORS['mac_green']]:
            btn = tk.Canvas(btn_frame, width=12, height=12, bg=COLORS['bg_main'],
                          highlightthickness=0)
            btn.pack(side=tk.LEFT, padx=2)
            btn.create_oval(2, 2, 10, 10, fill=color, outline='')
        
        # 标题
        tk.Label(header, text="ICMP 差错报文分析", 
                font=FONTS['title'], 
                fg=COLORS['text_primary'],
                bg=COLORS['bg_main']).pack(side=tk.LEFT, padx=(16, 4))
        
        # 版本标签
        version_frame = tk.Frame(header, bg=COLORS['accent_light'], 
                                highlightbackground=COLORS['accent_blue'],
                                highlightthickness=1)
        version_frame.pack(side=tk.LEFT, pady=8)
        tk.Label(version_frame, text="v2.0.0", 
                font=FONTS['small'],
                fg=COLORS['accent_blue'],
                bg=COLORS['accent_light']).pack(padx=8, pady=2)
        
        # 右侧按钮组
        right_frame = tk.Frame(header, bg=COLORS['bg_main'])
        right_frame.pack(side=tk.RIGHT)
        
        # 导航标签
        nav_commands = {
            '控制': self._show_control_menu,
            '统计': self._show_statistics,
            '帮助': self._show_help
        }
        for text, command in nav_commands.items():
            btn = tk.Button(right_frame, text=text, 
                           bg=COLORS['bg_main'], fg=COLORS['text_secondary'],
                           font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                           padx=12, pady=4, command=command)
            btn.pack(side=tk.LEFT, padx=4)
            if text == '控制':
                self.control_btn = btn
        
        # 工具按钮（含下拉箭头，跟随导航按钮风格）
        self.tools_container = tk.Frame(right_frame, bg=COLORS['bg_main'])
        self.tools_container.pack(side=tk.LEFT, padx=4)
        
        self.tools_btn = tk.Button(
            self.tools_container,
            text='工具',
            bg=COLORS['bg_main'], fg=COLORS['text_secondary'],
            font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
            padx=0, pady=4, bd=0,
            command=self._show_tools_menu
        )
        self.tools_btn.pack(side=tk.LEFT)
        
        tools_arrow = tk.Button(
            self.tools_container,
            text='\u25be',
            font=('Microsoft YaHei', 10),
            bg=COLORS['bg_main'], fg=COLORS['text_secondary'],
            relief=tk.FLAT, cursor='hand2',
            padx=2, pady=4, bd=0,
            command=self._show_tools_menu
        )
        tools_arrow.pack(side=tk.LEFT, padx=(0, 12))
            
        # Dark主题切换按钮
        dark_btn = tk.Button(right_frame, text="Dark", 
                            bg=COLORS['text_primary'], fg='white',
                            font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                            padx=16, pady=4, command=self._toggle_dark_mode)
        dark_btn.pack(side=tk.LEFT, padx=(12, 0))
        
    def _create_left_panel(self, parent):
        """创建左侧控制面板"""
        # 数据源卡片
        card = tk.Frame(parent, bg=COLORS['bg_card'], 
                       highlightbackground=COLORS['border'],
                       highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # 数据源标题
        tk.Label(card, text="数据源", 
                font=FONTS['label_bold'],
                fg=COLORS['text_primary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, padx=16, pady=(16, 12))
        
        # 模式选择按钮组
        mode_frame = tk.Frame(card, bg=COLORS['bg_card'])
        mode_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
        
        self.mode_var = tk.StringVar(value="offline")
        self.mode_buttons = {}
        
        modes = [
            ("离线文件", "offline"),
            ("实时抓包", "live"),
            ("测试样本", "sample"),
        ]
        
        for i, (text, value) in enumerate(modes):
            if i == 0:
                btn = tk.Button(mode_frame, text=text, 
                              bg=COLORS['accent_blue'], fg='white',
                              font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                              command=lambda v=value: self._select_mode(v))
            else:
                btn = tk.Button(mode_frame, text=text,
                              bg=COLORS['bg_highlight'], fg=COLORS['text_secondary'],
                              font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                              command=lambda v=value: self._select_mode(v))
            btn.pack(fill=tk.X, pady=(0, 8), ipady=8)
            self.mode_buttons[value] = btn
        
        # 文件路径
        tk.Label(card, text="文件路径", 
                font=FONTS['small'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, padx=16, pady=(0, 8))
        
        path_frame = tk.Frame(card, bg=COLORS['bg_card'])
        path_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
        
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(path_frame, textvariable=self.file_path_var,
                                   font=FONTS['small'],
                                   fg=COLORS['text_primary'],
                                   bg=COLORS['bg_card'],
                                   relief=tk.SOLID, bd=1,
                                   highlightbackground=COLORS['border'])
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6)
        self.file_entry.insert(0, "选择 .pcap 文件...")
        
        self.file_paths: List[str] = []
        
        self.batch_btn = tk.Button(path_frame, text="批量导入",
                 bg=COLORS['accent_blue'], fg='white',
                 font=FONTS['small'], relief=tk.FLAT,
                 cursor='hand2',
                 command=self._batch_import_files)
        self.batch_btn.pack(side=tk.RIGHT, padx=(4, 0))
        
        self.browse_btn = tk.Button(path_frame, text="浏览",
                              bg=COLORS['accent_blue'], fg='white',
                              font=FONTS['small'], relief=tk.FLAT,
                              cursor='hand2',
                              command=self._browse_file)
        self.browse_btn.pack(side=tk.RIGHT, padx=(4, 0))
        
        tk.Button(path_frame, text="✕", width=3,
                 bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                 font=FONTS['small'], relief=tk.FLAT,
                 command=self._clear_file_path).pack(side=tk.RIGHT, padx=(4, 4))
        
        # 网络接口
        tk.Label(card, text="网络接口", 
                font=FONTS['label'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, padx=16, pady=(0, 8))
        
        self.interface_var = tk.StringVar()
        interfaces = get_network_interfaces()
        if interfaces:
            self.interface_var.set(interfaces[0])
        
        interface_frame = tk.Frame(card, bg=COLORS['bg_card'])
        interface_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
        
        select_frame = tk.Frame(interface_frame, bg=COLORS['bg_card'], relief=tk.SOLID, bd=1)
        select_frame.pack(fill=tk.X)
        
        self.interface_label = tk.Label(select_frame, textvariable=self.interface_var,
                                       font=FONTS['label'], fg=COLORS['text_primary'],
                                       bg=COLORS['bg_card'], anchor=tk.W)
        self.interface_label.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(4, 0))
        
        arrow_btn = tk.Button(select_frame, text="▼", font=FONTS['label'],
                             bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                             relief=tk.FLAT, cursor='hand2',
                             command=lambda: self._show_interface_list(interface_frame))
        arrow_btn.pack(side=tk.RIGHT, padx=4)
        
        select_frame.bind('<Button-1>', lambda e: self._show_interface_list(interface_frame))
        
        self.interface_popup = None
        
        # 抓包参数（可展开区域）
        param_header = tk.Frame(card, bg=COLORS['bg_card'], cursor='hand2')
        param_header.pack(fill=tk.X, padx=16, pady=(0, 8))
        param_header.bind('<Button-1>', lambda e: self._toggle_params())
        
        tk.Label(param_header, text="抓包参数", 
                font=FONTS['label'], fg=COLORS['text_primary'],
                bg=COLORS['bg_card']).pack(side=tk.LEFT)
        
        self.param_arrow = tk.Label(param_header, text="▾", 
                                     font=FONTS['label'],
                                     fg=COLORS['text_secondary'],
                                     bg=COLORS['bg_card'])
        self.param_arrow.pack(side=tk.RIGHT)
        
        # 抓包参数区域（可收起/展开）
        self.param_frame = tk.Frame(card, bg=COLORS['bg_card'])
        self.param_frame.pack(fill=tk.X, padx=16, pady=(0, 8))
        self.param_visible = True
        
        # 抓包数量
        tk.Label(self.param_frame, text="抓包数量", 
                font=FONTS['label'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, pady=(0, 4))
        self.count_var = tk.StringVar(value="0")
        count_entry = tk.Entry(self.param_frame, textvariable=self.count_var,
                              font=FONTS['label'],
                              fg=COLORS['text_primary'],
                              bg=COLORS['bg_card'],
                              relief=tk.SOLID, bd=1,
                              highlightbackground=COLORS['border'])
        count_entry.pack(fill=tk.X, pady=(0, 12), ipady=6)
        
        # 超时时间
        tk.Label(self.param_frame, text="超时时间 (秒)", 
                font=FONTS['label'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, pady=(0, 4))
        self.timeout_var = tk.StringVar(value="0")
        timeout_entry = tk.Entry(self.param_frame, textvariable=self.timeout_var,
                                font=FONTS['label'],
                                fg=COLORS['text_primary'],
                                bg=COLORS['bg_card'],
                                relief=tk.SOLID, bd=1,
                                highlightbackground=COLORS['border'])
        timeout_entry.pack(fill=tk.X, ipady=6)
        
        # 操作按钮（始终显示，不属于抓包参数）
        self.btn_frame = tk.Frame(card, bg=COLORS['bg_card'])
        self.btn_frame.pack(fill=tk.X, padx=16, pady=(0, 8))
        
        self.start_btn = tk.Button(self.btn_frame, text="开始分析",
                                  bg=COLORS['accent_blue'], fg='white',
                                  font=FONTS['label_bold'],
                                  relief=tk.FLAT, cursor='hand2',
                                  command=self._start_analysis)
        self.start_btn.pack(fill=tk.X, pady=(0, 8), ipady=12)
        
        action_frame = tk.Frame(self.btn_frame, bg=COLORS['bg_card'])
        action_frame.pack(fill=tk.X)
        
        tk.Button(action_frame, text="清空结果",
                 bg=COLORS['bg_highlight'], fg=COLORS['text_primary'],
                 font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                 command=self._clear_results).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        
        tk.Button(action_frame, text="生成报告",
                 bg=COLORS['bg_highlight'], fg=COLORS['text_primary'],
                 font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                 command=self._show_statistics).pack(side=tk.RIGHT, fill=tk.X, expand=True, ipady=8, padx=(8, 0))
        
        # 状态栏（始终显示）
        status_frame = tk.Frame(card, bg=COLORS['bg_card'])
        status_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
        
        self.status_var = tk.StringVar(value="● 就绪")
        tk.Label(status_frame, textvariable=self.status_var, 
                font=FONTS['label'], fg=COLORS['accent_green'],
                bg=COLORS['bg_card']).pack(side=tk.LEFT)
        
        self.total_count_var = tk.StringVar(value="报文总数: 0")
        tk.Label(status_frame, textvariable=self.total_count_var,
                font=FONTS['label'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(side=tk.RIGHT)
        
        self._on_mode_change()
        
    def _toggle_params(self):
        """切换参数区域显示/隐藏"""
        if self.param_visible:
            self.param_frame.pack_forget()
            self.param_arrow.config(text="▸")
        else:
            self.param_frame.pack(fill=tk.X, padx=16, pady=(0, 8), before=self.btn_frame)
            self.param_arrow.config(text="▾")
        self.param_visible = not self.param_visible
        
    def _select_mode(self, mode):
        """选择抓包模式"""
        self.mode_var.set(mode)
        
        for value, btn in self.mode_buttons.items():
            if value == mode:
                btn.config(bg=COLORS['accent_blue'], fg='white')
            else:
                btn.config(bg=COLORS['bg_highlight'], fg=COLORS['text_secondary'])
        
        self._on_mode_change()
        
    def _on_mode_change(self):
        """模式切换响应"""
        mode = self.mode_var.get()
        
        if mode == "live":
            self.file_entry.config(state=tk.DISABLED)
            self.browse_btn.config(state=tk.DISABLED)
            self.batch_btn.config(state=tk.DISABLED)
            self.interface_label.config(state=tk.NORMAL)
        elif mode == "offline":
            self.file_entry.config(state=tk.NORMAL)
            self.browse_btn.config(state=tk.NORMAL)
            self.batch_btn.config(state=tk.NORMAL)
            self.interface_label.config(state=tk.DISABLED)
        else:
            self.file_entry.config(state=tk.DISABLED)
            self.browse_btn.config(state=tk.DISABLED)
            self.batch_btn.config(state=tk.DISABLED)
            self.interface_label.config(state=tk.DISABLED)
            
    def _create_right_panel(self, parent):
        """创建右侧主显示区"""
        # 顶部标签栏
        top_tabs = tk.Frame(parent, bg=COLORS['bg_main'])
        top_tabs.pack(fill=tk.X, pady=(0, 8))
        
        self.top_tab_var = tk.StringVar(value="overview")
        top_tab_names = [("概览", "overview")]
        
        self.top_tab_buttons = {}
        
        for text, value in top_tab_names:
            btn = tk.Button(top_tabs, text=text,
                          bg=COLORS['accent_blue'], fg='white',
                          font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                          padx=16, pady=4)
            btn.pack(side=tk.LEFT)
            self.top_tab_buttons[value] = btn
        
        # 复制全部按钮
        tk.Button(top_tabs, text="复制全部",
                 bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                 font=FONTS['small'], relief=tk.SOLID, bd=1,
                 highlightbackground=COLORS['border'],
                 cursor='hand2', command=self._copy_all).pack(side=tk.RIGHT, padx=4, ipady=2)
        
        # 主内容卡片
        main_card = tk.Frame(parent, bg=COLORS['bg_card'],
                            highlightbackground=COLORS['border'],
                            highlightthickness=1)
        main_card.pack(fill=tk.BOTH, expand=True)
        
        # 空状态显示
        self.empty_frame = tk.Frame(main_card, bg=COLORS['bg_card'])
        self.empty_frame.pack(fill=tk.BOTH, expand=True)
        
        # 空状态图标
        icon_canvas = tk.Canvas(self.empty_frame, width=80, height=80,
                               bg=COLORS['bg_card'], highlightthickness=0)
        icon_canvas.pack(pady=(120, 16))
        icon_canvas.create_oval(5, 5, 75, 75, outline='#d1d8e0', width=2)
        icon_canvas.create_line(25, 40, 38, 55, 58, 25,
                               fill='#d1d8e0', width=3, capstyle=tk.ROUND)
        
        tk.Label(self.empty_frame, text="暂无解析数据",
                font=FONTS['subtitle'], fg=COLORS['text_primary'],
                bg=COLORS['bg_card']).pack()
        
        tk.Label(self.empty_frame, text="请选择 pcap 文件或开始实时抓包",
                font=FONTS['small'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(pady=(8, 16))
        
        # 数据列表（初始隐藏）
        self.data_frame = tk.Frame(main_card, bg=COLORS['bg_card'])
        
        # 搜索和过滤栏
        search_frame = tk.Frame(self.data_frame, bg=COLORS['bg_card'])
        search_frame.pack(fill=tk.X, padx=12, pady=(12, 0))
        
        tk.Label(search_frame, text="搜索:", font=FONTS['label'], 
                 fg=COLORS['text_secondary'], bg=COLORS['bg_card']).pack(side=tk.LEFT, padx=(0, 6))
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                                     font=FONTS['label'], width=24,
                                     bg=COLORS['bg_highlight'], fg=COLORS['text_primary'],
                                     relief=tk.FLAT)
        self.search_entry.pack(side=tk.LEFT)
        self.search_var.trace('w', lambda *args: self._filter_packets())
        
        # 搜索字段选择器
        self.search_field_var = tk.StringVar(value="全部")
        search_fields = ["全部", "序号", "类型", "代码", "校验和", "标识符", 
                        "序列号", "源IP", "目的IP", "分类", "验证"]
        
        self.search_field_container = tk.Frame(search_frame, bg=COLORS['bg_card'])
        self.search_field_container.pack(side=tk.LEFT, padx=(4, 12))
        
        self.search_field_btn = tk.Button(
            self.search_field_container,
            textvariable=self.search_field_var,
            font=('Microsoft YaHei', 12),
            bg=COLORS['bg_highlight'], fg=COLORS['text_secondary'],
            activebackground=COLORS['bg_highlight'], activeforeground=COLORS['text_secondary'],
            relief=tk.FLAT, cursor='hand2',
            padx=8, pady=3, bd=0,
            command=self._show_search_field_menu
        )
        self.search_field_btn.pack(side=tk.LEFT)
        
        sf_arrow = tk.Button(
            self.search_field_container,
            text='\u25be',
            font=('Microsoft YaHei', 8),
            bg=COLORS['bg_highlight'], fg=COLORS['text_secondary'],
            relief=tk.FLAT, cursor='hand2',
            padx=2, pady=3, bd=0,
            command=self._show_search_field_menu
        )
        sf_arrow.pack(side=tk.LEFT, padx=(0, 4))
        
        self.search_field_menu = tk.Menu(self.root, tearoff=0,
                                         font=('Microsoft YaHei', 12),
                                         bg='white', fg=COLORS['text_primary'],
                                         activebackground=COLORS['accent_light'],
                                         activeforeground=COLORS['accent_blue'])
        for f in search_fields:
            self.search_field_menu.add_command(label=f, font=('Microsoft YaHei', 12),
                                               command=lambda opt=f: self._select_search_field(opt))
        
        # 过滤标签
        filter_label = tk.Label(search_frame, text="过滤", font=FONTS['label'], 
                                fg=COLORS['text_secondary'], bg=COLORS['bg_card'])
        filter_label.pack(side=tk.LEFT, padx=(16, 6))
        
        self.filter_var = tk.StringVar(value="全部")
        filter_options = ["全部", "查询报文", "差错报文", 
                         "Echo Request", "Echo Reply", 
                         "Destination Unreachable", "Time Exceeded", 
                         "Redirect", "Parameter Problem"]
        
        # 美化过滤下拉按钮（圆角风格）
        self.filter_container = tk.Frame(search_frame, bg=COLORS['bg_card'])
        self.filter_container.pack(side=tk.LEFT)
        
        self.filter_btn = tk.Button(
            self.filter_container,
            textvariable=self.filter_var,
            font=('Microsoft YaHei', 13),
            bg=COLORS['bg_highlight'], fg=COLORS['accent_blue'],
            activebackground=COLORS['accent_light'], activeforeground=COLORS['accent_blue'],
            relief=tk.FLAT, cursor='hand2',
            padx=14, pady=6,
            bd=0,
            command=self._show_filter_menu
        )
        self.filter_btn.pack(side=tk.LEFT)
        
        # 下拉箭头
        arrow_btn = tk.Button(
            self.filter_container,
            text='\u25be',  # ▾
            font=('Microsoft YaHei', 10),
            bg=COLORS['bg_highlight'], fg=COLORS['accent_blue'],
            activebackground=COLORS['accent_light'], activeforeground=COLORS['accent_blue'],
            relief=tk.FLAT, cursor='hand2',
            padx=2, pady=6,
            bd=0,
            command=self._show_filter_menu
        )
        arrow_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        def on_hover_enter(e):
            self.filter_btn.config(bg=COLORS['accent_light'])
            arrow_btn.config(bg=COLORS['accent_light'])
        def on_hover_leave(e):
            self.filter_btn.config(bg=COLORS['bg_highlight'])
            arrow_btn.config(bg=COLORS['bg_highlight'])
        
        self.filter_btn.bind('<Enter>', on_hover_enter)
        self.filter_btn.bind('<Leave>', on_hover_leave)
        arrow_btn.bind('<Enter>', on_hover_enter)
        arrow_btn.bind('<Leave>', on_hover_leave)
        
        self.filter_menu = tk.Menu(self.root, tearoff=0,
                                   font=('Microsoft YaHei', 13),
                                   bg='white', fg=COLORS['text_primary'],
                                   activebackground=COLORS['accent_light'],
                                   activeforeground=COLORS['accent_blue'])
        for option in filter_options:
            self.filter_menu.add_command(label=option, font=('Microsoft YaHei', 13),
                                        command=lambda opt=option: self._select_filter(opt))
        
        # 报文列表
        list_frame = tk.Frame(self.data_frame, bg=COLORS['bg_card'])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(8, 12))
        
        tree_style = ttk.Style()
        tree_style.configure('Treeview', font=('Microsoft YaHei', 14), rowheight=35)
        tree_style.configure('Treeview.Heading', font=('Microsoft YaHei', 14, 'bold'))
        
        columns = ('序号', '类型', '代码', '校验和', '标识符', '序列号', '源IP', '目的IP', '分类', '验证')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, 
                                        show='headings', height=12)
        
        col_widths = {
            '序号': 70, '类型': 180, '代码': 70, '校验和': 100, 
            '标识符': 80, '序列号': 80, '源IP': 130, '目的IP': 130, 
            '分类': 90, '验证': 80
        }
        for col in columns:
            self.packet_tree.heading(col, text=col, 
                                    command=lambda c=col: self._sort_tree(c))
            self.packet_tree.column(col, width=col_widths.get(col, 100), anchor=tk.CENTER)
        
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=vsb.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_tree.bind('<<TreeviewSelect>>', self._on_packet_select)
        
        # 底部详情标签
        bottom_tabs = tk.Frame(self.data_frame, bg=COLORS['bg_card'])
        bottom_tabs.pack(fill=tk.X, padx=12, pady=(0, 8))
        
        self.bottom_tab_var = tk.StringVar(value="fields")
        bottom_tab_names = [("字段解析", "fields"), ("原始数据", "raw"), ("统计信息", "stats")]
        
        self.bottom_tab_buttons = {}
        
        for text, value in bottom_tab_names:
            if value == "fields":
                btn = tk.Button(bottom_tabs, text=text,
                              bg=COLORS['accent_light'], fg=COLORS['accent_blue'],
                              font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                              padx=16, pady=4)
            else:
                btn = tk.Button(bottom_tabs, text=text,
                              bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                              font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                              padx=16, pady=4)
            btn.pack(side=tk.LEFT, padx=(0, 8))
            btn.bind('<Button-1>', lambda e, v=value: self._switch_bottom_tab(v))
            self.bottom_tab_buttons[value] = btn
        
        # 详情内容区
        self.detail_frame = tk.Frame(self.data_frame, bg=COLORS['bg_card'])
        self.detail_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))
        
        # 字段解析（默认显示）
        self.fields_text = scrolledtext.ScrolledText(
            self.detail_frame, wrap=tk.WORD,
            font=FONTS['mono'],
            bg=COLORS['bg_card'], fg=COLORS['text_primary'],
            relief=tk.FLAT, bd=0,
            highlightthickness=1,
            highlightbackground=COLORS['border'],
            padx=12, pady=8
        )
        self.fields_text.pack(fill=tk.BOTH, expand=True)
        self.fields_text.insert(tk.END, "选中一条报文后在此查看详细字段解析\n")
        self.fields_text.config(state=tk.DISABLED)
        
        # 原始数据（初始隐藏）
        self.raw_text = scrolledtext.ScrolledText(
            self.detail_frame, wrap=tk.WORD,
            font=FONTS['mono'],
            bg=COLORS['bg_card'], fg=COLORS['text_primary'],
            relief=tk.FLAT, bd=0,
            highlightthickness=1,
            highlightbackground=COLORS['border'],
            padx=12, pady=8
        )
        
        # 统计信息（初始隐藏）
        self.stats_frame = tk.Frame(self.detail_frame, bg=COLORS['bg_card'])
        
        self.stats_text = scrolledtext.ScrolledText(
            self.stats_frame, wrap=tk.WORD,
            font=FONTS['mono'],
            bg=COLORS['bg_card'], fg=COLORS['text_primary'],
            relief=tk.FLAT, bd=0,
            highlightthickness=1,
            highlightbackground=COLORS['border'],
            padx=12, pady=8,
            height=6
        )
        self.stats_text.pack(fill=tk.X, pady=(0, 8))
        self.stats_text.insert(tk.END, "选中一条报文后在此查看统计信息\n")
        self.stats_text.config(state=tk.DISABLED)
        
    def _switch_bottom_tab(self, tab):
        """切换底部详情标签"""
        self.bottom_tab_var.set(tab)
        
        for value, btn in self.bottom_tab_buttons.items():
            if value == tab:
                btn.config(bg=COLORS['accent_light'], fg=COLORS['accent_blue'])
            else:
                btn.config(bg=COLORS['bg_card'], fg=COLORS['text_secondary'])
        
        self.fields_text.pack_forget()
        self.raw_text.pack_forget()
        self.stats_frame.pack_forget()
        
        if tab == "fields":
            self.fields_text.pack(fill=tk.BOTH, expand=True)
        elif tab == "raw":
            self.raw_text.pack(fill=tk.BOTH, expand=True)
        elif tab == "stats":
            self.stats_frame.pack(fill=tk.BOTH, expand=True)
            self._update_stats_view()
            
    def _update_stats_view(self):
        """更新统计信息视图"""
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        if hasattr(self, 'stats_canvas'):
            self.stats_canvas.get_tk_widget().pack_forget()
            plt.close('all')
        
        if not self.packets:
            self.stats_text.insert(tk.END, "暂无统计数据\n")
        else:
            stats = self.analyzer.get_statistics()
            
            self.stats_text.insert(tk.END, f"报文总数: {stats['total_packets']}\n")
            self.stats_text.insert(tk.END, f"差错报文数: {stats['error_packets']}\n")
            self.stats_text.insert(tk.END, f"校验和错误数: {stats['checksum_errors']}\n")
            self.stats_text.insert(tk.END, "\n报文类型分布:\n")
            for ptype, count in stats['type_distribution'].items():
                type_name = self.analyzer.TYPE_DESCRIPTIONS.get(ptype, f"未知类型 ({ptype})")
                self.stats_text.insert(tk.END, f"  {type_name}: {count}\n")
            
            self._create_stats_chart(stats)
        
        self.stats_text.config(state=tk.DISABLED)
    
    def _create_stats_chart(self, stats):
        """创建统计图表"""
        type_dist = stats['type_distribution']
        if not type_dist:
            return
        
        labels = []
        counts = []
        colors = []
        
        type_colors = {
            0: '#27ae60',
            3: '#e74c3c',
            4: '#9b59b6',
            5: '#1abc9c',
            8: '#4a90e2',
            11: '#ff9500',
            12: '#c0392b',
            13: '#3498db',
            14: '#2ecc71',
            15: '#f39c12',
            16: '#8e44ad'
        }
        
        for ptype, count in type_dist.items():
            desc = self.analyzer.TYPE_DESCRIPTIONS.get(ptype, f"类型 {ptype}")
            # 将标签在括号前换行：英文部分 + 换行 + 中文括号部分
            if ' (' in desc:
                en_part, cn_part = desc.split(' (', 1)
                short_label = en_part + '\n(' + cn_part
            else:
                short_label = desc
            labels.append(short_label)
            counts.append(count)
            colors.append(type_colors.get(ptype, '#95a5a6'))
        
        fig, ax = plt.subplots(figsize=(16, 4.8), dpi=100)
        fig.patch.set_facecolor('white')
        
        bars = ax.bar(range(len(labels)), counts, color=colors, 
                     edgecolor='none', width=0.5)
        
        ax.set_xlabel('ICMP类型', fontsize=13, fontfamily='Microsoft YaHei')
        ax.set_ylabel('数量', fontsize=13, fontfamily='Microsoft YaHei')
        ax.set_title('ICMP报文类型分布', fontsize=15, fontweight='bold',
                    fontfamily='Microsoft YaHei', pad=15)
        ax.set_ylim(0, max(counts) * 1.3)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=0, ha='center', fontsize=9,
                          fontfamily='Microsoft YaHei', linespacing=1.3)
        ax.tick_params(axis='both', labelsize=11)
        
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height}', ha='center', va='bottom', fontsize=12)
        
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('#d1d8e0')
        ax.spines['bottom'].set_color('#d1d8e0')
        
        fig.subplots_adjust(top=0.85, bottom=0.42)
        
        if hasattr(self, 'stats_canvas'):
            self.stats_canvas.get_tk_widget().pack_forget()
        
        self.stats_canvas = FigureCanvasTkAgg(fig, master=self.stats_frame)
        self.stats_canvas.draw()
        self.stats_canvas.get_tk_widget().pack(fill=tk.X, expand=True)
        
    def _browse_file(self):
        """浏览文件"""
        file_path = filedialog.askopenfilename(
            title="选择pcap文件",
            filetypes=[("PCAP文件", "*.pcap"), ("PCAPNG文件", "*.pcapng"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            
    def _clear_file_path(self):
        """清除文件路径"""
        self.file_path_var.set("")
        self.file_paths.clear()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, "选择 .pcap 文件...")
        
    def _batch_import_files(self):
        """批量导入文件"""
        file_paths = filedialog.askopenfilenames(
            title="选择多个pcap文件",
            filetypes=[("PCAP文件", "*.pcap"), ("PCAPNG文件", "*.pcapng"), ("所有文件", "*.*")]
        )
        if file_paths:
            self.file_paths = list(file_paths)
            if len(file_paths) == 1:
                self.file_path_var.set(file_paths[0])
                self.file_entry.delete(0, tk.END)
                self.file_entry.insert(0, file_paths[0])
            else:
                display_text = f"已选择 {len(file_paths)} 个文件"
                self.file_path_var.set(display_text)
                self.file_entry.delete(0, tk.END)
                self.file_entry.insert(0, display_text)
        
    def _show_data_view(self):
        """显示数据视图"""
        self.empty_frame.pack_forget()
        self.data_frame.pack(fill=tk.BOTH, expand=True)
        
    def _show_empty_view(self):
        """显示空状态"""
        self.data_frame.pack_forget()
        self.empty_frame.pack(fill=tk.BOTH, expand=True)
        
    def _start_analysis(self):
        """开始分析"""
        if self.is_capturing:
            self._stop_capture()
            return
            
        mode = self.mode_var.get()
        
        if mode == "offline":
            if self.file_paths:
                self._start_offline_analysis_batch(self.file_paths)
            else:
                file_path = self.file_path_var.get()
                if not file_path or file_path == "选择 .pcap 文件...":
                    messagebox.showwarning("提示", "请先选择pcap文件")
                    return
                self._start_offline_analysis(file_path)
        elif mode == "live":
            self._start_live_capture()
        elif mode == "sample":
            self._start_sample_analysis()
            
    def _start_offline_analysis_batch(self, file_paths: List[str]):
        """批量离线分析"""
        self._clear_results()
        self._show_data_view()
        
        try:
            count = 0
            for file_path in file_paths:
                reader = OfflinePacketReader(file_path)
                for packet_data in reader.read():
                    result = self.analyzer.analyze_packet(packet_data)
                    if result:
                        self.packets.append(result)
                        self._add_packet_to_tree(result, count + 1)
                        count += 1
                        
            self.total_count_var.set(f"报文总数: {count}")
            self.status_var.set(f"✓ 分析完成 ({len(file_paths)}个文件)")
            
        except Exception as e:
            messagebox.showerror("错误", f"分析失败: {e}")
            self.status_var.set("✗ 分析失败")
            
    def _start_offline_analysis(self, file_path: str):
        """开始离线分析"""
        self._clear_results()
        self._show_data_view()
        
        try:
            reader = OfflinePacketReader(file_path)
            count = 0
            for packet_data in reader.read():
                result = self.analyzer.analyze_packet(packet_data)
                if result:
                    self.packets.append(result)
                    self._add_packet_to_tree(result, count + 1)
                    count += 1
                    
            self.total_count_var.set(f"报文总数: {count}")
            self.status_var.set("✓ 分析完成")
            
        except Exception as e:
            messagebox.showerror("错误", f"分析失败: {e}")
            self.status_var.set("✗ 分析失败")
            
    def _start_live_capture(self):
        """开始实时抓包"""
        self._clear_results()
        self._show_data_view()
        
        interface = self.interface_var.get()
        timeout = int(self.timeout_var.get() or 0)
        count = int(self.count_var.get() or 0)
        
        self.is_capturing = True
        self.capture_start_time = time.time()
        self.start_btn.config(text="停止抓包", bg=COLORS['accent_red'])
        self.status_var.set("● 正在抓包...")
        
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, timeout, count)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self._process_queue()
        
    def _capture_worker(self, interface: str, timeout: int, count: int):
        """抓包工作线程"""
        try:
            reader = LivePacketReader(interface, timeout, count)
            for packet_data in reader.read():
                if not self.is_capturing:
                    break
                self.packet_queue.put(packet_data)
        except Exception as e:
            self.packet_queue.put(f"ERROR:{e}")
            
    def _process_queue(self):
        """处理抓包队列"""
        if not self.is_capturing:
            return
            
        try:
            while True:
                packet_data = self.packet_queue.get_nowait()
                if isinstance(packet_data, str) and packet_data.startswith("ERROR:"):
                    error_msg = packet_data[6:]
                    self.status_var.set(f"✗ {error_msg}")
                    self._stop_capture()
                    return
                    
                result = self.analyzer.analyze_packet(packet_data)
                if result:
                    self.packets.append(result)
                    self._add_packet_to_tree(result, len(self.packets))
                    self.total_count_var.set(f"报文总数: {len(self.packets)}")
                    
        except queue.Empty:
            pass
            
        if self.is_capturing:
            self.root.after(100, self._process_queue)
            
    def _stop_capture(self):
        """停止抓包"""
        self.is_capturing = False
        self.start_btn.config(text="开始分析", bg=COLORS['accent_blue'])
        self.status_var.set("✓ 抓包完成")
        
    def _start_sample_analysis(self):
        """开始测试样本分析"""
        self._clear_results()
        self._show_data_view()
        
        samples = create_sample_icmp_packets()
        for i, packet_data in enumerate(samples):
            result = self.analyzer.analyze_packet(packet_data)
            if result:
                self.packets.append(result)
                self._add_packet_to_tree(result, len(self.packets))
                
        self.total_count_var.set(f"报文总数: {len(self.packets)}")
        self.status_var.set("✓ 测试样本分析完成")
        
    def _add_packet_to_tree(self, packet: ICMPPacket, index: int):
        """添加报文到列表"""
        type_name = self.analyzer.TYPE_DESCRIPTIONS.get(packet.header.type, f"未知类型 ({packet.header.type})")
        code_str = str(packet.header.code)
        checksum = f"0x{packet.header.checksum:04X}"
        ident = f"0x{packet.header.identifier:04X}" if packet.header.identifier else "-"
        seq = str(packet.header.sequence) if packet.header.sequence else "-"
        
        src_ip = packet.original_ip_header.source_ip if packet.original_ip_header else "-"
        dst_ip = packet.original_ip_header.dest_ip if packet.original_ip_header else "-"
        
        category = "查询报文" if self.analyzer.is_query_message(packet.header.type) else "差错报文"
        
        # 校验和验证状态
        if packet.checksum_valid:
            verify_status = "✅ 通过"
        else:
            verify_status = "❌ 失败"
        
        self.packet_tree.insert('', tk.END, values=(
            index, type_name, code_str, checksum, ident, seq, src_ip, dst_ip, category, verify_status
        ))
        
    def _on_packet_select(self, event):
        """报文选中事件"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        index = int(self.packet_tree.item(item, 'values')[0]) - 1
        if 0 <= index < len(self.packets):
            packet = self.packets[index]
            self._update_detail_view(packet)
            
    def _update_detail_view(self, packet: ICMPPacket):
        """更新详情视图"""
        self.fields_text.config(state=tk.NORMAL)
        self.fields_text.delete(1.0, tk.END)
        
        # 配置文本标签颜色
        self.fields_text.tag_config('checksum_pass', background='#e8f8f0', foreground='#27ae60')
        self.fields_text.tag_config('checksum_fail', background='#fde8e8', foreground='#e74c3c')
        self.fields_text.tag_config('header', font=('Microsoft YaHei', 14, 'bold'))
        
        output = self.analyzer.format_output(packet)
        
        # 逐行插入，并为校验和相关行添加高亮
        lines = output.split('\n')
        for line in lines:
            if '校验和验证' in line:
                if '通过' in line:
                    self.fields_text.insert(tk.END, line + '\n', 'checksum_pass')
                else:
                    self.fields_text.insert(tk.END, line + '\n', 'checksum_fail')
            elif '校验和' in line or '计算校验和' in line:
                if packet.checksum_valid:
                    self.fields_text.insert(tk.END, line + '\n', 'checksum_pass')
                else:
                    self.fields_text.insert(tk.END, line + '\n', 'checksum_fail')
            else:
                if line.startswith('==') or line.startswith('【'):
                    self.fields_text.insert(tk.END, line + '\n', 'header')
                else:
                    self.fields_text.insert(tk.END, line + '\n')
        
        self.fields_text.config(state=tk.DISABLED)
        
        self.raw_text.config(state=tk.NORMAL)
        self.raw_text.delete(1.0, tk.END)
        if packet.raw_data:
            hex_str = packet.raw_data.hex()
            formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            for i in range(0, len(formatted), 48):
                self.raw_text.insert(tk.END, formatted[i:i+48] + '\n')
        self.raw_text.config(state=tk.DISABLED)
        
    def _clear_results(self):
        """清空结果"""
        self.packets.clear()
        self.analyzer = ICMPAnalyzer()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.total_count_var.set("报文总数: 0")
        self.status_var.set("● 就绪")
        self._show_empty_view()
        
    def _show_statistics(self):
        """显示统计信息"""
        if not self.packets:
            messagebox.showinfo("统计信息", "暂无数据")
            return
            
        stats = self.analyzer.get_statistics()
        
        report = f"""
ICMP报文分析统计报告
{'='*50}
报文总数: {stats['total_packets']}
差错报文数: {stats['error_packets']}
校验和错误数: {stats['checksum_errors']}

报文类型分布:
"""
        for ptype, count in stats['type_distribution'].items():
            type_name = self.analyzer.TYPE_DESCRIPTIONS.get(ptype, f"未知类型 ({ptype})")
            percentage = (count / stats['total_packets']) * 100
            report += f"  {type_name}: {count} ({percentage:.1f}%)\n"
            
        messagebox.showinfo("统计报告", report)
        
    def _sort_tree(self, col):
        """排序树形列表"""
        if self.sort_column == col:
            self.sort_order = 'desc' if self.sort_order == 'asc' else 'asc'
        else:
            self.sort_column = col
            self.sort_order = 'asc'
            
        items = [(self.packet_tree.set(item, col), item) 
                for item in self.packet_tree.get_children('')]
                
        try:
            items.sort(key=lambda x: float(x[0]), reverse=(self.sort_order == 'desc'))
        except ValueError:
            items.sort(key=lambda x: x[0], reverse=(self.sort_order == 'desc'))
            
        for index, (_, item) in enumerate(items):
            self.packet_tree.move(item, '', index)
            
    def _show_search_field_menu(self):
        """显示搜索字段选择菜单"""
        x = self.search_field_container.winfo_rootx()
        y = self.search_field_container.winfo_rooty() + self.search_field_container.winfo_height()
        self.search_field_menu.tk_popup(x, y)

    def _select_search_field(self, field):
        """选择搜索字段"""
        self.search_field_var.set(field)
        self._filter_packets()

    def _show_filter_menu(self):
        """显示过滤菜单"""
        x = self.filter_btn.winfo_rootx()
        y = self.filter_btn.winfo_rooty() + self.filter_btn.winfo_height()
        self.filter_menu.tk_popup(x, y)
        
    def _select_filter(self, option):
        """选择过滤选项"""
        self.filter_var.set(option)
        self._filter_packets()
        
    # 搜索字段 → 列索引映射
    SEARCH_FIELD_INDEX = {
        '序号': 0, '类型': 1, '代码': 2, '校验和': 3,
        '标识符': 4, '序列号': 5, '源IP': 6, '目的IP': 7, '分类': 8, '验证': 9
    }

    def _filter_packets(self):
        """过滤和搜索报文"""
        search_text = self.search_var.get().lower()
        filter_type = self.filter_var.get()
        search_field = self.search_field_var.get()
        
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item, 'values')
            visible = True
            
            if search_text:
                if search_field == '全部':
                    # 全局搜索：匹配任意列
                    match_found = any(search_text in str(v).lower() for v in values)
                else:
                    idx = self.SEARCH_FIELD_INDEX.get(search_field)
                    match_found = search_text in str(values[idx]).lower() if idx is not None else True
                if not match_found:
                    visible = False
                    
            if filter_type != "全部" and visible:
                packet_type = str(values[1])
                category = str(values[8])
                
                if filter_type == "查询报文" and category != "查询报文":
                    visible = False
                elif filter_type == "差错报文" and category != "差错报文":
                    visible = False
                elif filter_type in ["Echo Request", "Echo Reply", 
                                     "Destination Unreachable", "Time Exceeded", 
                                     "Redirect", "Parameter Problem"]:
                    if filter_type not in packet_type:
                        visible = False
                        
            self.packet_tree.item(item, tags=('visible',) if visible else ('hidden',))
            
        self.packet_tree.tag_configure('hidden', foreground='#bdc3c7')
        self.packet_tree.tag_configure('visible', foreground=COLORS['text_primary'])
            
    def _copy_all(self):
        """复制全部数据"""
        if not self.packets:
            return
            
        text = ""
        for i, packet in enumerate(self.packets, 1):
            text += f"=== 报文 {i} ===\n"
            text += self.analyzer.format_output(packet)
            text += "\n\n"
            
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        
    def _show_control_menu(self):
        """显示控制菜单"""
        menu = tk.Menu(self.root, tearoff=0,
                       font=('Microsoft YaHei', 13),
                       bg='white', fg=COLORS['text_primary'],
                       activebackground=COLORS['accent_light'],
                       activeforeground=COLORS['accent_blue'])
        menu.add_command(label="开始分析", command=self._start_analysis)
        menu.add_command(label="停止分析", command=self._stop_capture)
        menu.add_separator()
        menu.add_command(label="清空结果", command=self._clear_results)
        menu.add_command(label="退出", command=self.root.quit)
        x = self.control_btn.winfo_rootx()
        y = self.control_btn.winfo_rooty() + self.control_btn.winfo_height()
        menu.tk_popup(x, y)

    def _show_tools_menu(self):
        """显示工具菜单"""
        menu = tk.Menu(self.root, tearoff=0,
                       font=('Microsoft YaHei', 13),
                       bg='white', fg=COLORS['text_primary'],
                       activebackground=COLORS['accent_light'],
                       activeforeground=COLORS['accent_blue'])
        menu.add_command(label="生成报告", command=self._show_statistics)
        menu.add_command(label="导出结果", command=self._export_results)
        menu.add_separator()
        menu.add_command(label="选择网卡", command=self._select_interface)
        x = self.tools_container.winfo_rootx()
        y = self.tools_container.winfo_rooty() + self.tools_container.winfo_height()
        menu.tk_popup(x, y)
        
    def _show_help(self):
        """显示帮助信息"""
        help_text = """ICMP差错报文分析 v2.0

功能说明：
- 离线文件：分析pcap格式的抓包文件
- 实时抓包：直接从网卡抓取ICMP报文
- 测试样本：使用内置测试数据进行分析

操作指南：
1. 选择数据源模式
2. 设置抓包参数（可选）
3. 点击"开始分析"按钮
4. 在右侧查看分析结果

快捷键：
- Ctrl+S：开始/停止分析
- Ctrl+P：停止抓包
- Ctrl+C：清空结果
- Ctrl+E：导出为CSV文件

版本：v2.0
作者：ICMP Analyzer Team"""
        messagebox.showinfo("帮助", help_text)
        
    def _toggle_dark_mode(self):
        """切换Dark/Light主题"""
        messagebox.showinfo("主题切换", "Dark模式功能正在开发中，敬请期待！")
        
    def _select_interface(self):
        """选择网络接口"""
        messagebox.showinfo("选择网卡", "请在左侧控制面板中选择网络接口")
        
    def _export_results(self):
        """导出结果"""
        if not self.packets:
            messagebox.showwarning("导出结果", "暂无数据可导出")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("\ufeff")  # BOM，解决Excel打开CSV中文乱码
                    f.write("序号,类型,代码,校验和,校验通过,标识符,序列号,源IP,目的IP,分类\n")
                    for i, packet in enumerate(self.packets, 1):
                        type_name = self.analyzer.TYPE_DESCRIPTIONS.get(packet.header.type, f"类型 {packet.header.type}")
                        category = "查询报文" if self.analyzer.is_query_message(packet.header.type) else "差错报文"
                        src_ip = packet.original_ip_header.source_ip if packet.original_ip_header else "-"
                        dst_ip = packet.original_ip_header.dest_ip if packet.original_ip_header else "-"
                        valid = "通过" if packet.checksum_valid else "失败"
                        f.write(f"{i},{type_name},{packet.header.code},{hex(packet.header.checksum)},{valid},")
                        f.write(f"{packet.header.identifier},{packet.header.sequence},{src_ip},{dst_ip},{category}\n")
                messagebox.showinfo("导出成功", f"结果已导出到：{file_path}")
            except Exception as e:
                messagebox.showerror("导出失败", f"导出失败: {str(e)}")
                
    def _show_interface_list(self, parent):
        """显示自定义网络接口下拉列表"""
        if self.interface_popup and self.interface_popup.winfo_exists():
            self.interface_popup.destroy()
        
        self.interface_popup = tk.Toplevel(self.root)
        self.interface_popup.overrideredirect(True)
        
        x = parent.winfo_rootx()
        y = parent.winfo_rooty() + parent.winfo_height()
        width = parent.winfo_width()
        
        interfaces = get_network_interfaces()
        height = len(interfaces) * 30 + 4
        
        self.interface_popup.geometry(f"{width}x{height}+{x}+{y}")
        
        listbox = tk.Listbox(self.interface_popup, font=FONTS['label'],
                            bg=COLORS['bg_card'], fg=COLORS['text_primary'],
                            selectbackground=COLORS['accent_blue'],
                            selectforeground='white', relief=tk.SOLID, bd=1,
                            highlightthickness=0)
        
        for interface in get_network_interfaces():
            listbox.insert(tk.END, interface)
        
        def on_select(event):
            selection = listbox.curselection()
            if selection:
                self.interface_var.set(listbox.get(selection[0]))
                self.interface_popup.destroy()
        
        def on_click_outside(event):
            if not listbox.winfo_containing(event.x_root, event.y_root):
                self.interface_popup.destroy()
        
        listbox.bind('<<ListboxSelect>>', on_select)
        self.interface_popup.bind('<Button-1>', on_click_outside)
        
        listbox.pack(fill=tk.BOTH, expand=True)
        listbox.focus_set()


def main():
    """主函数"""
    root = tk.Tk()
    
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
        
    app = ICMPAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
