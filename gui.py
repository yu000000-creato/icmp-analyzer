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
    'title': ('Microsoft YaHei', 14, 'bold'),
    'subtitle': ('Microsoft YaHei', 12),
    'label': ('Microsoft YaHei', 10),
    'label_bold': ('Microsoft YaHei', 10, 'bold'),
    'small': ('Microsoft YaHei', 9),
    'tiny': ('Microsoft YaHei', 8),
    'mono': ('Consolas', 9),
    'mono_small': ('Consolas', 8),
}


class ICMPAnalyzerGUI:
    """ICMP分析器图形界面 v2.0"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ICMP 差错报文分析 v2.0")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)
        self.root.configure(bg=COLORS['bg_main'])
        
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
        paned = tk.PanedWindow(body, orient=tk.HORIZONTAL, bg=COLORS['bg_main'],
                              sashrelief=tk.FLAT, sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # 左侧控制面板
        left_panel = tk.Frame(paned, bg=COLORS['bg_card'])
        paned.add(left_panel, width=320)
        
        # 右侧主显示区
        right_panel = tk.Frame(paned, bg=COLORS['bg_main'])
        paned.add(right_panel, width=1040)
        
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
        tk.Label(version_frame, text="v2.0", 
                font=FONTS['small'],
                fg=COLORS['accent_blue'],
                bg=COLORS['accent_light']).pack(padx=8, pady=2)
        
        # 右侧按钮组
        right_frame = tk.Frame(header, bg=COLORS['bg_main'])
        right_frame.pack(side=tk.RIGHT)
        
        # 导航标签
        for text in ['控制', '统计', '工具', '帮助']:
            btn = tk.Button(right_frame, text=text, 
                           bg=COLORS['bg_main'], fg=COLORS['text_secondary'],
                           font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                           padx=12, pady=4)
            btn.pack(side=tk.LEFT, padx=4)
            
        # Dark主题切换按钮
        dark_btn = tk.Button(right_frame, text="Dark", 
                            bg=COLORS['text_primary'], fg='white',
                            font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                            padx=16, pady=4)
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
        
        tk.Button(path_frame, text="✕", width=3,
                 bg=COLORS['bg_card'], fg=COLORS['text_secondary'],
                 font=FONTS['small'], relief=tk.FLAT,
                 command=self._clear_file_path).pack(side=tk.RIGHT, padx=(4, 0))
        
        # 网络接口
        tk.Label(card, text="网络接口", 
                font=FONTS['small'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, padx=16, pady=(0, 8))
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(card, textvariable=self.interface_var,
                                            font=FONTS['small'], state='readonly')
        self.interface_combo['values'] = get_network_interfaces()
        if self.interface_combo['values']:
            self.interface_combo.current(0)
        self.interface_combo.pack(fill=tk.X, padx=16, pady=(0, 16), ipady=4)
        
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
        
        self.param_frame = tk.Frame(card, bg=COLORS['bg_card'])
        self.param_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
        self.param_visible = True
        
        # 抓包数量
        tk.Label(self.param_frame, text="抓包数量", 
                font=FONTS['small'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, pady=(0, 4))
        self.count_var = tk.StringVar(value="0")
        count_entry = tk.Entry(self.param_frame, textvariable=self.count_var,
                              font=FONTS['small'],
                              fg=COLORS['text_primary'],
                              bg=COLORS['bg_card'],
                              relief=tk.SOLID, bd=1,
                              highlightbackground=COLORS['border'])
        count_entry.pack(fill=tk.X, pady=(0, 12), ipady=6)
        
        # 超时时间
        tk.Label(self.param_frame, text="超时时间 (秒)", 
                font=FONTS['small'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(anchor=tk.W, pady=(0, 4))
        self.timeout_var = tk.StringVar(value="0")
        timeout_entry = tk.Entry(self.param_frame, textvariable=self.timeout_var,
                                font=FONTS['small'],
                                fg=COLORS['text_primary'],
                                bg=COLORS['bg_card'],
                                relief=tk.SOLID, bd=1,
                                highlightbackground=COLORS['border'])
        timeout_entry.pack(fill=tk.X, ipady=6)
        
        # 操作按钮
        btn_frame = tk.Frame(card, bg=COLORS['bg_card'])
        btn_frame.pack(fill=tk.X, padx=16, pady=(8, 16))
        
        self.start_btn = tk.Button(btn_frame, text="开始分析",
                                  bg=COLORS['accent_blue'], fg='white',
                                  font=FONTS['label_bold'],
                                  relief=tk.FLAT, cursor='hand2',
                                  command=self._start_analysis)
        self.start_btn.pack(fill=tk.X, pady=(0, 8), ipady=12)
        
        action_frame = tk.Frame(card, bg=COLORS['bg_card'])
        action_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
        
        tk.Button(action_frame, text="清空结果",
                 bg=COLORS['bg_highlight'], fg=COLORS['text_primary'],
                 font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                 command=self._clear_results).pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        
        tk.Button(action_frame, text="生成报告",
                 bg=COLORS['bg_highlight'], fg=COLORS['text_primary'],
                 font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                 command=self._show_statistics).pack(side=tk.RIGHT, fill=tk.X, expand=True, ipady=8, padx=(8, 0))
        
        # 状态栏
        status_frame = tk.Frame(card, bg=COLORS['bg_card'])
        status_frame.pack(fill=tk.X, padx=16, pady=(8, 16))
        
        self.status_var = tk.StringVar(value="● 就绪")
        tk.Label(status_frame, textvariable=self.status_var, 
                font=FONTS['small'], fg=COLORS['accent_green'],
                bg=COLORS['bg_card']).pack(side=tk.LEFT)
        
        self.total_count_var = tk.StringVar(value="报文总数: 0")
        tk.Label(status_frame, textvariable=self.total_count_var,
                font=FONTS['small'], fg=COLORS['text_secondary'],
                bg=COLORS['bg_card']).pack(side=tk.RIGHT)
        
        self._on_mode_change()
        
    def _toggle_params(self):
        """切换参数区域显示/隐藏"""
        if self.param_visible:
            self.param_frame.pack_forget()
            self.param_arrow.config(text="▸")
        else:
            self.param_frame.pack(fill=tk.X, padx=16, pady=(0, 16))
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
            self.interface_combo.config(state='readonly')
        elif mode == "offline":
            self.file_entry.config(state=tk.NORMAL)
            self.interface_combo.config(state=tk.DISABLED)
        else:
            self.file_entry.config(state=tk.DISABLED)
            self.interface_combo.config(state=tk.DISABLED)
            
    def _create_right_panel(self, parent):
        """创建右侧主显示区"""
        # 顶部标签栏
        top_tabs = tk.Frame(parent, bg=COLORS['bg_main'])
        top_tabs.pack(fill=tk.X, pady=(0, 8))
        
        self.top_tab_var = tk.StringVar(value="overview")
        top_tab_names = [("概览", "overview"), ("类型", "type"), ("代码", "code"), 
                        ("检验和", "checksum"), ("分类", "category")]
        
        for text, value in top_tab_names:
            if value == "overview":
                btn = tk.Button(top_tabs, text=text,
                              bg=COLORS['accent_blue'], fg='white',
                              font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                              padx=16, pady=4)
            else:
                btn = tk.Button(top_tabs, text=text,
                              bg=COLORS['bg_main'], fg=COLORS['text_secondary'],
                              font=FONTS['label'], relief=tk.FLAT, cursor='hand2',
                              padx=16, pady=4)
            btn.pack(side=tk.LEFT)
            btn.bind('<Button-1>', lambda e, v=value: self._switch_top_tab(v))
        
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
        
        self.empty_start_btn = tk.Button(self.empty_frame, text="选择文件开始",
                                        bg=COLORS['accent_light'],
                                        fg=COLORS['accent_blue'],
                                        font=FONTS['label'],
                                        relief=tk.SOLID, bd=1,
                                        highlightbackground=COLORS['accent_blue'],
                                        cursor='hand2', padx=24, pady=8,
                                        command=self._browse_file)
        self.empty_start_btn.pack()
        
        # 数据列表（初始隐藏）
        self.data_frame = tk.Frame(main_card, bg=COLORS['bg_card'])
        
        # 报文列表
        list_frame = tk.Frame(self.data_frame, bg=COLORS['bg_card'])
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        
        columns = ('序号', '类型', '代码', '校验和', '标识符', '序列号', '源IP', '目的IP', '分类')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, 
                                        show='headings', height=12)
        
        col_widths = {'序号': 50, '类型': 80, '代码': 60, '校验和': 80, 
                     '标识符': 70, '序列号': 70, '源IP': 120, '目的IP': 120, '分类': 100}
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
        self.stats_text = scrolledtext.ScrolledText(
            self.detail_frame, wrap=tk.WORD,
            font=FONTS['mono'],
            bg=COLORS['bg_card'], fg=COLORS['text_primary'],
            relief=tk.FLAT, bd=0,
            highlightthickness=1,
            highlightbackground=COLORS['border'],
            padx=12, pady=8
        )
        
    def _switch_top_tab(self, tab):
        """切换顶部标签"""
        self.top_tab_var.set(tab)
        
    def _switch_bottom_tab(self, tab):
        """切换底部详情标签"""
        self.bottom_tab_var.set(tab)
        
        self.fields_text.pack_forget()
        self.raw_text.pack_forget()
        self.stats_text.pack_forget()
        
        if tab == "fields":
            self.fields_text.pack(fill=tk.BOTH, expand=True)
        elif tab == "raw":
            self.raw_text.pack(fill=tk.BOTH, expand=True)
        elif tab == "stats":
            self.stats_text.pack(fill=tk.BOTH, expand=True)
            self._update_stats_view()
            
    def _update_stats_view(self):
        """更新统计信息视图"""
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        if not self.packets:
            self.stats_text.insert(tk.END, "暂无统计数据\n")
        else:
            stats = self.analyzer.get_statistics()
            self.stats_text.insert(tk.END, f"报文总数: {stats['total_packets']}\n")
            self.stats_text.insert(tk.END, f"差错报文数: {stats['error_packets']}\n")
            self.stats_text.insert(tk.END, f"校验和错误数: {stats['checksum_errors']}\n")
            self.stats_text.insert(tk.END, "\n报文类型分布:\n")
            for ptype, count in stats['type_distribution'].items():
                self.stats_text.insert(tk.END, f"  {ptype}: {count}\n")
        
        self.stats_text.config(state=tk.DISABLED)
        
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
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, "选择 .pcap 文件...")
        
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
            file_path = self.file_path_var.get()
            if not file_path or file_path == "选择 .pcap 文件...":
                messagebox.showwarning("提示", "请先选择pcap文件")
                return
            self._start_offline_analysis(file_path)
        elif mode == "live":
            self._start_live_capture()
        elif mode == "sample":
            self._start_sample_analysis()
            
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
                self._add_packet_to_tree(result, i + 1)
                
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
        
        self.packet_tree.insert('', tk.END, values=(
            index, type_name, code_str, checksum, ident, seq, src_ip, dst_ip, category
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
        
        output = self.analyzer.format_output(packet)
        self.fields_text.insert(tk.END, output)
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
            percentage = (count / stats['total_packets']) * 100
            report += f"  {ptype}: {count} ({percentage:.1f}%)\n"
            
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
