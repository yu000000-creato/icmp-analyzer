"""
ICMP差错报文分析程序 - 专业工业级网络抓包工具UI
深色暗黑主题，三栏布局：控制栏 | 报文列表 | 详情面板
"""

import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import ttkbootstrap as ttkbs
from ttkbootstrap.constants import *
from ttkbootstrap.style import Style
from ttkbootstrap.dialogs import Messagebox
from typing import Optional, List, Dict, Any
import threading
import queue
import time
import re
from pathlib import Path

from icmp_analyzer import ICMPAnalyzer, ICMPPacket, ICMPType
from packet_reader import (
    LivePacketReader, OfflinePacketReader, BinarySampleReader,
    create_sample_icmp_packets, get_network_interfaces
)

# ========== 全局配色方案 ==========
COLORS = {
    'bg_main': '#1a1d24',
    'bg_card': '#242830',
    'bg_highlight': '#2a2f38',
    'accent_blue': '#2382de',
    'accent_orange': '#ff9500',
    'accent_green': '#27ae60',
    'accent_red': '#e74c3c',
    'accent_yellow': '#f39c12',
    'text_primary': '#e8edf2',
    'text_secondary': '#9aa3b2',
    'text_disabled': '#5a6270',
    'border': '#3a3f4a',
    'hover': '#2d333b',
    'error_bg': '#3d2a2a',
    'warning_bg': '#3d352a',
    'success_bg': '#2a3d2a',
}

# ========== 字体配置 ==========
FONTS = {
    'title': ('Microsoft YaHei', 12, 'bold'),
    'label': ('Microsoft YaHei', 10),
    'label_bold': ('Microsoft YaHei', 10, 'bold'),
    'small': ('Microsoft YaHei', 9),
    'tiny': ('Microsoft YaHei', 8),
    'mono': ('Consolas', 9),
    'mono_small': ('Consolas', 8),
}


class ICMPAnalyzerGUI:
    """ICMP分析器图形界面 - 专业工业级UI"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ICMP差错报文分析程序 v1.0.0")
        self.root.geometry("1400x900")
        self.root.minsize(1400, 900)
        
        self.style = Style()
        self.style.theme_use('darkly')
        
        self._configure_custom_styles()
        
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
        
    def _configure_custom_styles(self):
        """配置自定义样式"""
        style = self.style
        
        style.configure('Card.TFrame', background=COLORS['bg_card'])
        style.configure('Accent.TFrame', background=COLORS['bg_highlight'])
        
        style.configure('Title.TLabel', font=FONTS['title'], foreground=COLORS['text_primary'])
        style.configure('Label.TLabel', font=FONTS['label'], foreground=COLORS['text_primary'])
        style.configure('Small.TLabel', font=FONTS['small'], foreground=COLORS['text_secondary'])
        style.configure('Mono.TLabel', font=FONTS['mono'], foreground=COLORS['text_primary'])
        
        style.configure('Treeview', 
                       background=COLORS['bg_card'],
                       foreground=COLORS['text_primary'],
                       fieldbackground=COLORS['bg_card'],
                       font=FONTS['mono'],
                       rowheight=24)
        style.configure('Treeview.Heading',
                       background=COLORS['accent_blue'],
                       foreground=COLORS['text_primary'],
                       font=FONTS['label_bold'])
        style.map('Treeview',
                 background=[('selected', COLORS['accent_blue'])],
                 foreground=[('selected', COLORS['text_primary'])])
        
        style.configure('Treeview.OddRow', background=COLORS['bg_card'])
        style.configure('Treeview.EvenRow', background=COLORS['bg_highlight'])
        style.configure('Treeview.ErrorRow', background=COLORS['error_bg'])
        style.configure('Treeview.WarningRow', background=COLORS['warning_bg'])
        
        style.configure('Custom.TButton', 
                       font=FONTS['label'], 
                       borderwidth=0,
                       background=COLORS['bg_highlight'],
                       foreground=COLORS['text_primary'])
        style.map('Custom.TButton',
                 background=[('active', COLORS['hover'])])
        
        style.configure('ModeSelected.TButton', 
                       font=FONTS['label'], 
                       borderwidth=0,
                       background=COLORS['accent_blue'],
                       foreground='white')
        style.map('ModeSelected.TButton',
                 background=[('active', '#1a6bb8')])
        
        style.configure('Start.TButton', 
                       background=COLORS['accent_green'],
                       foreground='white',
                       font=FONTS['label'],
                       borderwidth=0)
        style.map('Start.TButton',
                 background=[('active', '#219a52'), ('disabled', COLORS['text_disabled'])])
        
        style.configure('Stop.TButton', 
                       background=COLORS['accent_red'],
                       foreground='white',
                       font=FONTS['label'],
                       borderwidth=0)
        style.map('Stop.TButton',
                 background=[('active', '#c0392b'), ('disabled', COLORS['text_disabled'])])
        
        style.configure('Clear.TButton', 
                       background=COLORS['bg_highlight'],
                       foreground=COLORS['text_primary'],
                       font=FONTS['label'],
                       borderwidth=0)
        style.map('Clear.TButton',
                 background=[('active', '#333944')])
        
        style.configure('Report.TButton', 
                       background=COLORS['accent_blue'],
                       foreground='white',
                       font=FONTS['label'],
                       borderwidth=0)
        style.map('Report.TButton',
                 background=[('active', '#1a6bb8')])
        
        style.configure('Export.TButton', 
                       background=COLORS['accent_orange'],
                       foreground='white',
                       font=FONTS['label'],
                       borderwidth=0)
        style.map('Export.TButton',
                 background=[('active', '#e08600')])
        
        style.configure('Status.TFrame', background=COLORS['bg_card'])
        style.configure('Status.TLabel', font=FONTS['small'], foreground=COLORS['text_secondary'])
        
    def _create_widgets(self):
        """创建界面组件"""
        main_frame = ttk.Frame(self.root, style='Card.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        self._create_title_bar(main_frame)
        
        body = ttk.Frame(main_frame, style='Card.TFrame')
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        
        sidebar = ttk.Frame(body, width=int(1400 * 0.18), style='Card.TFrame')
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        sidebar.pack_propagate(False)
        
        main_area = ttk.Frame(body)
        main_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        middle_frame = ttk.Frame(main_area, width=int(1400 * 0.42), style='Card.TFrame')
        middle_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 8))
        middle_frame.pack_propagate(False)
        
        right_frame = ttk.Frame(main_area, width=int(1400 * 0.40), style='Card.TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH)
        right_frame.pack_propagate(False)
        
        self._create_sidebar(sidebar)
        self._create_packet_list(middle_frame)
        self._create_detail_panel(right_frame)
        self._create_status_bar(main_frame)
        
    def _create_title_bar(self, parent):
        """标题栏"""
        title_bar = ttk.Frame(parent, style='Accent.TFrame', height=48)
        title_bar.pack(fill=tk.X)
        title_bar.pack_propagate(False)
        
        left_frame = ttk.Frame(title_bar, style='Accent.TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(left_frame, text="🌐 ICMP差错报文分析程序", 
                               style='Title.TLabel')
        title_label.pack(side=tk.LEFT, padx=15)
        
        version_label = ttk.Label(left_frame, text="v1.0.0",
                                 font=('Consolas', 9),
                                 foreground=COLORS['text_secondary'])
        version_label.pack(side=tk.LEFT, padx=5)
        
        center_frame = ttk.Frame(title_bar, style='Accent.TFrame')
        center_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        subtitle_label = ttk.Label(center_frame, text="专业网络抓包分析工具",
                                   font=FONTS['small'],
                                   foreground=COLORS['text_secondary'])
        subtitle_label.pack(side=tk.TOP, pady=(14, 0))
        
        right_frame = ttk.Frame(title_bar, style='Accent.TFrame')
        right_frame.pack(side=tk.RIGHT, padx=15, pady=5)
        
        ttk.Label(right_frame, text="🎨 主题:",
                  font=FONTS['small'],
                  foreground=COLORS['text_secondary']).pack(side=tk.LEFT, padx=(0, 5))
        
        themes = ['darkly', 'cyborg', 'superhero']
        self.theme_var = tk.StringVar(value='darkly')
        theme_combo = ttk.Combobox(right_frame, textvariable=self.theme_var,
                                   values=themes, width=10, state='readonly')
        theme_combo.pack(side=tk.LEFT)
        theme_combo.bind('<<ComboboxSelected>>', self._on_theme_change)
        
    def _create_sidebar(self, parent):
        """侧边栏"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self._create_control_tab(notebook)
        self._create_stats_tab(notebook)
        self._create_tools_tab(notebook)
        self._create_about_tab(notebook)
        
    def _create_control_tab(self, parent):
        """控制标签页"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        parent.add(frame, text="⚙ 控制")
        
        canvas = tk.Canvas(frame, highlightthickness=0, bg=COLORS['bg_card'])
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable = ttk.Frame(canvas, style='Card.TFrame')
        
        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Label(scrollable, text="抓包模式", style='Label.TLabel').pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.mode_var = tk.StringVar(value="offline")
        mode_frame = ttk.Frame(scrollable, style='Card.TFrame')
        mode_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        modes = [
            ("📁 离线文件", "offline"),
            ("📡 实时抓包", "live"),
            ("🧪 测试样本", "sample"),
        ]
        
        tooltips = {
            "offline": "从pcap文件读取离线报文数据",
            "live": "从网络接口实时捕获ICMP报文",
            "sample": "使用内置测试样本进行分析"
        }
        
        for i, (text, value) in enumerate(modes):
            btn_style = 'ModeSelected.TButton' if value == "offline" else 'Custom.TButton'
            btn = ttk.Button(mode_frame, text=text, width=20,
                            command=lambda v=value: self._select_mode(v),
                            style=btn_style)
            btn.pack(fill=tk.X, pady=2)
            self._add_tooltip(btn, tooltips[value])
            setattr(self, f"mode_btn_{value}", btn)
        
        ttk.Label(scrollable, text="文件路径", style='Label.TLabel').pack(anchor=tk.W, padx=10, pady=(10, 5))
        file_frame = ttk.Frame(scrollable, style='Card.TFrame')
        file_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var,
                                    font=FONTS['mono_small'],
                                    foreground=COLORS['text_primary'],
                                    background=COLORS['bg_highlight'])
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.file_entry.insert(0, "点击浏览选择pcap文件...")
        
        ttk.Button(file_frame, text="✕", width=3,
                  command=self._clear_file_path,
                  style='Clear.TButton').pack(side=tk.RIGHT)
        
        ttk.Button(scrollable, text="📂 浏览文件", width=20,
                  command=self._browse_file,
                  style='Custom.TButton').pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(scrollable, text="网络接口", style='Label.TLabel').pack(anchor=tk.W, padx=10, pady=(10, 5))
        iface_frame = ttk.Frame(scrollable, style='Card.TFrame')
        iface_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(iface_frame, textvariable=self.interface_var,
                                            font=FONTS['mono_small'],
                                            state='readonly', width=22)
        self.interface_combo['values'] = get_network_interfaces()
        if self.interface_combo['values']:
            self.interface_combo.current(0)
        self.interface_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(iface_frame, text="🔄", width=3,
                  command=self._refresh_interfaces,
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        ttk.Label(scrollable, text="抓包参数", style='Label.TLabel').pack(anchor=tk.W, padx=10, pady=(10, 5))
        param_frame = ttk.Frame(scrollable, style='Card.TFrame')
        param_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(param_frame, text="抓包数量:", style='Small.TLabel').pack(anchor=tk.W, pady=(0, 3))
        self.count_var = tk.StringVar(value="0")
        count_entry = ttk.Entry(param_frame, textvariable=self.count_var,
                                font=FONTS['mono_small'], width=20)
        count_entry.pack(fill=tk.X, pady=(0, 5))
        count_entry.bind('<FocusOut>', self._validate_count)
        
        ttk.Label(param_frame, text="(0=无限制)", style='Small.TLabel').pack(anchor=tk.W, pady=(0, 8))
        
        ttk.Label(param_frame, text="超时时间(秒):", style='Small.TLabel').pack(anchor=tk.W, pady=(0, 3))
        self.timeout_var = tk.StringVar(value="10")
        timeout_entry = ttk.Entry(param_frame, textvariable=self.timeout_var,
                                  font=FONTS['mono_small'], width=20)
        timeout_entry.pack(fill=tk.X, pady=(0, 5))
        timeout_entry.bind('<FocusOut>', self._validate_timeout)
        
        ttk.Separator(scrollable, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(scrollable, text="操作", style='Label.TLabel').pack(anchor=tk.W, padx=10, pady=(0, 5))
        action_frame = ttk.Frame(scrollable, style='Card.TFrame')
        action_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.start_btn = ttk.Button(action_frame, text="▶ 开始分析",
                                   command=self._start_analysis,
                                   style='Start.TButton')
        self.start_btn.pack(fill=tk.X, pady=3)
        self._add_tooltip(self.start_btn, "开始ICMP报文分析（根据所选模式）")
        
        self.stop_btn = ttk.Button(action_frame, text="⏹ 停止",
                                  command=self._stop_capture,
                                  style='Stop.TButton',
                                  state=DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=3)
        self._add_tooltip(self.stop_btn, "停止当前抓包或分析")
        
        clear_btn = ttk.Button(action_frame, text="🗑 清空结果",
                  command=self._clear_results,
                  style='Clear.TButton')
        clear_btn.pack(fill=tk.X, pady=3)
        self._add_tooltip(clear_btn, "清空所有已解析的报文数据")
        
        report_btn = ttk.Button(action_frame, text="📊 生成报表",
                  command=self._show_statistics,
                  style='Report.TButton')
        report_btn.pack(fill=tk.X, pady=3)
        self._add_tooltip(report_btn, "生成详细的统计报表")
        
        export_btn = ttk.Button(action_frame, text="💾 导出",
                  command=self._export_results,
                  style='Export.TButton')
        export_btn.pack(fill=tk.X, pady=3)
        self._add_tooltip(export_btn, "导出分析结果到文件")
        
        self._on_mode_change()
        
    def _select_mode(self, mode):
        """选择抓包模式"""
        self.mode_var.set(mode)
        
        for m in ["offline", "live", "sample"]:
            btn = getattr(self, f"mode_btn_{m}")
            btn.config(style='ModeSelected.TButton' if m == mode else 'Custom.TButton')
        
        self._on_mode_change()
        
    def _validate_count(self, event):
        """验证抓包数量"""
        try:
            val = int(self.count_var.get())
            if val < 0:
                self.count_var.set("0")
                messagebox.showwarning("警告", "抓包数量不能为负数")
        except ValueError:
            self.count_var.set("0")
            messagebox.showwarning("警告", "请输入有效的数字")
            
    def _validate_timeout(self, event):
        """验证超时时间"""
        try:
            val = int(self.timeout_var.get())
            if val < 0:
                self.timeout_var.set("10")
                messagebox.showwarning("警告", "超时时间不能为负数")
        except ValueError:
            self.timeout_var.set("10")
            messagebox.showwarning("警告", "请输入有效的数字")
            
    def _clear_file_path(self):
        """清空文件路径"""
        self.file_path_var.set("")
        
    def _create_stats_tab(self, parent):
        """统计标签页"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        parent.add(frame, text="📊 统计")
        
        info_label = ttk.Label(frame, 
                               text="完成分析后\n查看统计信息",
                               font=FONTS['small'],
                               foreground=COLORS['text_secondary'],
                               justify=tk.CENTER)
        info_label.pack(expand=True, padx=20, pady=40)
        
        ttk.Button(frame, text="📊 生成报表",
                   command=self._show_statistics,
                   style='Report.TButton').pack(pady=10, padx=10, fill=tk.X)
        
    def _create_tools_tab(self, parent):
        """工具标签页"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        parent.add(frame, text="🔧 工具")
        
        tools = [
            ("🔄 刷新接口列表", self._refresh_interfaces),
            ("📋 复制当前报文", self._copy_current),
            ("📤 导出为JSON", self._export_json),
            ("📥 导入pcap", self._import_pcap),
        ]
        
        for text, cmd in tools:
            ttk.Button(frame, text=text, command=cmd,
                       style='Custom.TButton').pack(fill=tk.X, padx=10, pady=5)
        
    def _create_about_tab(self, parent):
        """关于标签页"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        parent.add(frame, text="ℹ 关于")
        
        about_text = """
🌐 ICMP差错报文分析程序

版本: v1.0.0
作者: Network Tools
日期: 2026

📋 功能特性:
• 实时网卡抓包
• 离线pcap解析
• 完整ICMP报文解析
• 校验和验证
• 统计报表导出

🔧 技术栈:
• Python 3.x
• Scapy
• ttkbootstrap
• Tkinter

📚 协议标准:
• RFC 792 - ICMP
"""
        text_widget = scrolledtext.ScrolledText(frame, wrap=tk.WORD,
                                                font=FONTS['small'],
                                                height=20,
                                                background=COLORS['bg_card'],
                                                foreground=COLORS['text_primary'])
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, about_text)
        text_widget.config(state=tk.DISABLED)
        
    def _refresh_interfaces(self):
        """刷新接口列表"""
        interfaces = get_network_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.current(0)
        messagebox.showinfo("提示", f"已刷新，共 {len(interfaces)} 个接口")
        
    def _copy_current(self):
        """复制当前报文"""
        if not self.packets:
            messagebox.showwarning("提示", "没有可复制的报文")
            return
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择报文")
            return
        item = selection[0]
        index = self.packet_tree.index(item)
        if index < len(self.packets):
            packet = self.packets[index]
            self.root.clipboard_clear()
            self.root.clipboard_append(self.analyzer.format_output(packet))
            messagebox.showinfo("成功", "已复制到剪贴板")
            
    def _export_json(self):
        """导出为JSON"""
        if not self.packets:
            messagebox.showwarning("提示", "没有可导出的数据")
            return
        import json
        file_path = filedialog.asksaveasfilename(
            title="导出JSON", defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        if not file_path:
            return
        try:
            data = []
            for i, pkt in enumerate(self.packets, 1):
                data.append({
                    "index": i,
                    "type": pkt.header.type,
                    "code": pkt.header.code,
                    "checksum": f"0x{pkt.header.checksum:04X}",
                    "checksum_valid": pkt.checksum_valid,
                    "description": pkt.description,
                    "raw_data": pkt.raw_data.hex()
                })
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("成功", f"已导出到: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
            
    def _import_pcap(self):
        """导入pcap"""
        file_path = filedialog.askopenfilename(
            title="选择pcap文件",
            filetypes=[("PCAP文件", "*.pcap"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self._select_mode("offline")
            self._start_analysis()
            
    def _on_theme_change(self, event):
        """主题切换"""
        theme = self.theme_var.get()
        self.style.theme_use(theme)
        
    def _create_packet_list(self, parent):
        """创建报文列表"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        columns = ('序号', '类型', '代码', '校验和', '分类', '描述')
        self.packet_tree = ttk.Treeview(frame, columns=columns, show='headings', 
                                         height=25)
        
        style = ttk.Style()
        style.configure('Treeview', font=FONTS['mono'])
        style.configure('Treeview.Heading', font=FONTS['label_bold'])
        
        for col in columns:
            self.packet_tree.heading(col, text=col, command=lambda c=col: self._sort_column(c))
        
        self.packet_tree.column('序号', width=60, anchor='center')
        self.packet_tree.column('类型', width=110, anchor='center')
        self.packet_tree.column('代码', width=60, anchor='center')
        self.packet_tree.column('校验和', width=100, anchor='center')
        self.packet_tree.column('分类', width=90, anchor='center')
        self.packet_tree.column('描述', width=200, anchor='w')
        
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_tree.bind('<<TreeviewSelect>>', self._on_packet_select)
        self.packet_tree.bind('<Double-1>', self._on_packet_double_click)
        
        self.empty_label = ttk.Label(frame, 
                                     text="📭\n暂无解析报文\n请开始抓包或加载离线文件",
                                     font=FONTS['label'],
                                     foreground=COLORS['text_disabled'],
                                     justify=tk.CENTER)
        self.empty_label.place(relx=0.5, rely=0.5, anchor='center')
        
    def _sort_column(self, col):
        """排序列"""
        if self.sort_column == col:
            self.sort_order = 'desc' if self.sort_order == 'asc' else 'asc'
        else:
            self.sort_column = col
            self.sort_order = 'asc'
            
        items = [(self.packet_tree.set(item, col), item) for item in self.packet_tree.get_children('')]
        
        try:
            items.sort(key=lambda x: int(x[0].split()[0]) if col == '序号' else x[0], 
                      reverse=(self.sort_order == 'desc'))
        except:
            items.sort(key=lambda x: x[0], reverse=(self.sort_order == 'desc'))
            
        for i, (val, item) in enumerate(items):
            self.packet_tree.move(item, '', i)
            
    def _create_detail_panel(self, parent):
        """创建详细信息面板"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        top_bar = ttk.Frame(frame, style='Accent.TFrame')
        top_bar.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(top_bar, text="📋 复制全部",
                   command=self._copy_all_details,
                   style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(top_bar, text="💾 导出单条",
                   command=self._export_single,
                   style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        
        notebook = ttk.Notebook(frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        fields_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(fields_frame, text="字段解析")
        self._create_fields_panel(fields_frame)
        
        raw_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(raw_frame, text="原始数据")
        self._create_raw_panel(raw_frame)
        
        stats_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(stats_frame, text="统计信息")
        self._create_stats_panel(stats_frame)
        
    def _copy_all_details(self):
        """复制全部详情"""
        if not self.packets:
            return
        selection = self.packet_tree.selection()
        if not selection:
            return
        item = selection[0]
        index = self.packet_tree.index(item)
        if index < len(self.packets):
            packet = self.packets[index]
            details = self.analyzer.format_output(packet)
            details += "\n\n=== 原始数据 ===\n" + packet.raw_data.hex()
            self.root.clipboard_clear()
            self.root.clipboard_append(details)
            messagebox.showinfo("成功", "已复制到剪贴板")
            
    def _export_single(self):
        """导出单条报文"""
        if not self.packets:
            messagebox.showwarning("提示", "没有可导出的数据")
            return
        selection = self.packet_tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先选择报文")
            return
        item = selection[0]
        index = self.packet_tree.index(item)
        if index < len(self.packets):
            packet = self.packets[index]
            file_path = filedialog.asksaveasfilename(
                title="导出单条报文",
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.analyzer.format_output(packet))
                    messagebox.showinfo("成功", f"已导出到: {file_path}")
                except Exception as e:
                    messagebox.showerror("错误", f"导出失败: {e}")
            
    def _create_fields_panel(self, parent):
        """创建字段解析面板"""
        self.fields_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, 
                                                     font=FONTS['mono'],
                                                     background=COLORS['bg_card'],
                                                     foreground=COLORS['text_primary'],
                                                     height=30)
        self.fields_text.pack(fill=tk.BOTH, expand=True)
        
    def _create_raw_panel(self, parent):
        """创建原始数据面板"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.raw_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, 
                                                  font=FONTS['mono'],
                                                  background=COLORS['bg_card'],
                                                  foreground=COLORS['text_primary'],
                                                  height=28)
        self.raw_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Button(frame, text="📋 复制十六进制",
                   command=self._copy_raw_hex,
                   style='Custom.TButton').pack(side=tk.RIGHT, padx=5, pady=5)
        
    def _copy_raw_hex(self):
        """复制原始十六进制"""
        content = self.raw_text.get('1.0', tk.END)
        hex_content = re.findall(r'[0-9A-Fa-f]+', content)
        self.root.clipboard_clear()
        self.root.clipboard_append(''.join(hex_content))
        messagebox.showinfo("成功", "已复制到剪贴板")
        
    def _create_stats_panel(self, parent):
        """创建统计面板"""
        frame = ttk.Frame(parent, style='Card.TFrame')
        frame.pack(fill=tk.BOTH, expand=True)
        
        cards_frame = ttk.Frame(frame, style='Card.TFrame')
        cards_frame.pack(fill=tk.X, pady=10, padx=10)
        
        self.stat_cards = {}
        card_data = [
            ("📦 总报文", "total", COLORS['accent_blue']),
            ("⚠ 差错报文", "error", COLORS['accent_orange']),
            ("❌ 校验和异常", "checksum_error", COLORS['accent_red']),
            ("✅ 有效报文", "valid", COLORS['accent_green']),
        ]
        
        for i, (label, key, color) in enumerate(card_data):
            card = ttk.Frame(cards_frame, style='Card.TFrame')
            card.grid(row=0, column=i, padx=5, sticky="nsew")
            cards_frame.grid_columnconfigure(i, weight=1)
            
            ttk.Label(card, text=label, font=FONTS['small'], 
                      foreground=COLORS['text_secondary']).pack(pady=(8, 2), padx=10)
            val_label = ttk.Label(card, text="0", font=FONTS['title'], 
                                 foreground=color)
            val_label.pack(pady=(2, 8), padx=10)
            self.stat_cards[key] = val_label
            
        chart_frame = ttk.Frame(frame, style='Card.TFrame')
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.chart_canvas = tk.Canvas(chart_frame, bg=COLORS['bg_card'],
                                       highlightthickness=0, height=200)
        self.chart_canvas.pack(fill=tk.BOTH, expand=True)
        
    def _create_status_bar(self, parent):
        """创建状态栏"""
        status_bar = ttk.Frame(parent, style='Status.TFrame', height=32)
        status_bar.pack(fill=tk.X)
        status_bar.pack_propagate(False)
        
        left_frame = ttk.Frame(status_bar, style='Status.TFrame')
        left_frame.pack(side=tk.LEFT, padx=15)
        
        self.status_var = tk.StringVar(value="● 就绪")
        status_label = ttk.Label(left_frame, textvariable=self.status_var, 
                                  font=FONTS['small'],
                                  foreground=COLORS['accent_green'])
        status_label.pack(side=tk.LEFT, padx=(0, 15))
        
        self.total_count_var = tk.StringVar(value="报文总数: 0")
        total_label = ttk.Label(left_frame, textvariable=self.total_count_var,
                                font=FONTS['small'],
                                foreground=COLORS['text_secondary'])
        total_label.pack(side=tk.LEFT)
        
        right_frame = ttk.Frame(status_bar, style='Status.TFrame')
        right_frame.pack(side=tk.RIGHT, padx=15)
        
        self.parsed_count_var = tk.StringVar(value="已解析: 0")
        parsed_label = ttk.Label(right_frame, textvariable=self.parsed_count_var,
                                  font=FONTS['small'],
                                  foreground=COLORS['text_secondary'])
        parsed_label.pack(side=tk.RIGHT, padx=(15, 0))
        
        self.capture_time_var = tk.StringVar(value="抓包时长: 00:00:00")
        time_label = ttk.Label(right_frame, textvariable=self.capture_time_var,
                                font=FONTS['small'],
                                foreground=COLORS['text_secondary'])
        time_label.pack(side=tk.RIGHT)
        
    def _on_mode_change(self):
        """模式切换响应"""
        mode = self.mode_var.get()
        
        if mode == "live":
            self.file_entry.config(state=DISABLED)
            self.interface_combo.config(state='readonly')
        elif mode == "offline":
            self.file_entry.config(state=NORMAL)
            self.interface_combo.config(state=DISABLED)
        else:
            self.file_entry.config(state=DISABLED)
            self.interface_combo.config(state=DISABLED)
            
    def _browse_file(self):
        """浏览文件"""
        file_path = filedialog.askopenfilename(
            title="选择pcap文件",
            filetypes=[
                ("PCAP文件", "*.pcap"),
                ("PCAPNG文件", "*.pcapng"),
                ("二进制文件", "*.bin"),
                ("所有文件", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
            
    def _start_analysis(self):
        """开始分析"""
        mode = self.mode_var.get()
        
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.is_capturing = True
        self.capture_start_time = time.time()
        
        self.analyzer = ICMPAnalyzer()
        self.packets.clear()
        
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        self.empty_label.place_forget()
        self.status_var.set("● 正在分析...")
        self.status_var.set("● 正在分析...")
        
        if mode == "sample":
            self._analyze_samples()
        elif mode == "offline":
            self._analyze_offline()
        else:
            self._analyze_live()
            
    def _analyze_samples(self):
        """分析测试样本"""
        try:
            samples = create_sample_icmp_packets()
            
            for i, sample in enumerate(samples, 1):
                if not self.is_capturing:
                    break
                    
                packet = self.analyzer.analyze_packet(sample)
                if packet:
                    self.packets.append(packet)
                    self._add_packet_to_list(i, packet)
                    
            self._finish_analysis()
            
        except Exception as e:
            messagebox.showerror("错误", f"分析失败: {e}")
            self._finish_analysis()
            
    def _analyze_offline(self):
        """分析离线文件"""
        file_path = self.file_path_var.get().strip()
        placeholder = "点击浏览选择pcap文件..."
        
        if not file_path or file_path == placeholder:
            messagebox.showwarning("警告", "请先选择一个pcap文件")
            self._finish_analysis()
            return
        
        path_obj = Path(file_path)
        
        if not path_obj.exists():
            messagebox.showerror("错误", f"文件不存在：\n{file_path}")
            self._finish_analysis()
            return
            
        if path_obj.is_dir():
            messagebox.showerror("错误", f"请选择文件而不是目录：\n{file_path}")
            self._finish_analysis()
            return
            
        valid_extensions = ('.pcap', '.pcapng', '.bin')
        if not file_path.lower().endswith(valid_extensions):
            messagebox.showwarning("警告", f"文件格式不支持！\n支持的格式：.pcap, .pcapng, .bin")
            self._finish_analysis()
            return
            
        def analyze_thread():
            try:
                reader = OfflinePacketReader(file_path)
                
                for i, data in enumerate(reader.read(), 1):
                    if not self.is_capturing:
                        break
                        
                    packet = self.analyzer.analyze_packet(data)
                    if packet:
                        self.packets.append(packet)
                        self.packet_queue.put((i, packet))
                        
                self.packet_queue.put(None)
                
            except Exception as e:
                self.packet_queue.put(("error", str(e)))
                
        threading.Thread(target=analyze_thread, daemon=True).start()
        self._process_queue()
        
    def _analyze_live(self):
        """实时抓包分析"""
        interface = self.interface_var.get()
        
        try:
            count = int(self.count_var.get())
            timeout = int(self.timeout_var.get())
        except ValueError:
            messagebox.showwarning("警告", "请输入有效的数值")
            self._finish_analysis()
            return
            
        def capture_thread():
            try:
                reader = LivePacketReader(
                    interface=interface if interface else None,
                    timeout=timeout,
                    packet_count=count
                )
                
                for i, data in enumerate(reader.read(), 1):
                    if not self.is_capturing:
                        break
                        
                    packet = self.analyzer.analyze_packet(data)
                    if packet:
                        self.packets.append(packet)
                        self.packet_queue.put((i, packet))
                        
                self.packet_queue.put(None)
                
            except PermissionError:
                self.packet_queue.put(("error", "需要管理员权限进行实时抓包"))
            except Exception as e:
                self.packet_queue.put(("error", str(e)))
                
        threading.Thread(target=capture_thread, daemon=True).start()
        self._process_queue()
        
    def _process_queue(self):
        """处理队列中的数据"""
        try:
            while True:
                item = self.packet_queue.get_nowait()

                if item is None:
                    self._finish_analysis()
                    return
                elif isinstance(item, tuple) and item[0] == "error":
                    messagebox.showerror("错误", item[1])
                    self._finish_analysis()
                    return
                else:
                    i, packet = item
                    try:
                        self._add_packet_to_list(i, packet)
                    except Exception as e:
                        # 单条报文解析失败不中断整体流程
                        import traceback as tb
                        print(f"[GUI] 报文 #{i} 显示失败: {e}")
                        tb.print_exc()

        except queue.Empty:
            pass

        if self.is_capturing:
            self._update_capture_time()
            self.root.after(100, self._process_queue)
            
    def _update_capture_time(self):
        """更新抓包时长"""
        elapsed = int(time.time() - self.capture_start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        self.capture_time_var.set(f"抓包时长: {hours:02d}:{minutes:02d}:{seconds:02d}")
        
    def _add_packet_to_list(self, index: int, packet: ICMPPacket):
        """添加报文到列表"""
        if self.analyzer.is_query_message(packet.header.type):
            category = "查询报文"
        elif self.analyzer.is_error_message(packet.header.type):
            category = "差错报文"
        else:
            category = "其他"
            
        desc = packet.description.split('\n')[0][:35]
        
        checksum_text = f"0x{packet.header.checksum:04X}"
        if not packet.checksum_valid:
            checksum_text += " ❌"
            
        item_id = self.packet_tree.insert('', 'end', values=(
            index,
            f"{packet.header.type} ({self.analyzer.TYPE_DESCRIPTIONS.get(packet.header.type, '未知')[:12]})",
            packet.header.code,
            checksum_text,
            category,
            desc
        ))
        
        row_tags = []
        
        if not packet.checksum_valid:
            row_tags.append('error')
        elif category == "差错报文":
            row_tags.append('warning')
        else:
            row_tags.append('odd' if len(self.packets) % 2 == 1 else 'even')
        
        if 'error' in row_tags:
            self.packet_tree.tag_configure('error', background=COLORS['error_bg'], foreground=COLORS['accent_red'])
        elif 'warning' in row_tags:
            self.packet_tree.tag_configure('warning', background=COLORS['warning_bg'], foreground=COLORS['accent_orange'])
        elif 'even' in row_tags:
            self.packet_tree.tag_configure('even', background=COLORS['bg_highlight'])
        else:
            self.packet_tree.tag_configure('odd', background=COLORS['bg_card'])
        
        self.packet_tree.item(item_id, tags=row_tags)
            
        self.total_count_var.set(f"报文总数: {len(self.packets)}")
        self.parsed_count_var.set(f"已解析: {len(self.packets)}")
        
    def _on_packet_select(self, event):
        """报文选择事件"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        index = self.packet_tree.index(item)
        
        if index < len(self.packets):
            packet = self.packets[index]
            self._display_packet_details(packet)
            
    def _on_packet_double_click(self, event):
        """报文双击事件"""
        self._on_packet_select(event)
        
    def _display_packet_details(self, packet: ICMPPacket):
        """显示报文详细信息"""
        self.fields_text.delete('1.0', tk.END)
        
        output = self.analyzer.format_output(packet)
        
        lines = output.split('\n')
        for line in lines:
            if '类型' in line or '代码' in line:
                self.fields_text.insert(tk.END, line + '\n', 'type_code')
            elif '校验和' in line:
                self.fields_text.insert(tk.END, line + '\n', 'checksum')
            elif 'IP' in line or '地址' in line:
                self.fields_text.insert(tk.END, line + '\n', 'ip')
            elif '错误' in line or '异常' in line:
                self.fields_text.insert(tk.END, line + '\n', 'error')
            else:
                self.fields_text.insert(tk.END, line + '\n')
                
        self.fields_text.tag_config('type_code', foreground=COLORS['accent_blue'])
        self.fields_text.tag_config('checksum', foreground=COLORS['accent_orange'])
        self.fields_text.tag_config('ip', foreground=COLORS['accent_green'])
        self.fields_text.tag_config('error', foreground=COLORS['accent_red'])
        
        self.raw_text.delete('1.0', tk.END)
        self.raw_text.insert(tk.END, "=== 原始数据 (十六进制) ===\n")
        
        raw_hex = packet.raw_data.hex()
        for i in range(0, len(raw_hex), 32):
            hex_part = raw_hex[i:i+32]
            offset = i // 2
            
            ascii_part = ''
            for j in range(0, len(hex_part), 2):
                if j + 1 < len(hex_part):
                    byte_val = int(hex_part[j:j+2], 16)
                    if 32 <= byte_val <= 126:
                        ascii_part += chr(byte_val)
                    else:
                        ascii_part += '.'
            
            self.raw_text.insert(tk.END, f"{offset:04X}  {hex_part}  |{ascii_part}|\n")
            
        self._update_stats_panel()
        
    def _update_stats_panel(self):
        """更新统计面板"""
        stats = self.analyzer.get_statistics()
        
        total = stats['total_packets']
        error_count = stats['error_packets']
        checksum_errors = stats['checksum_errors']
        valid_count = total - error_count - checksum_errors
        
        self.stat_cards['total'].config(text=str(total))
        self.stat_cards['error'].config(text=str(error_count))
        self.stat_cards['checksum_error'].config(text=str(checksum_errors))
        self.stat_cards['valid'].config(text=str(valid_count))
        
        self._draw_chart()
        
    def _draw_chart(self):
        """绘制统计图表"""
        canvas = self.chart_canvas
        canvas.delete("all")
        
        canvas.update_idletasks()
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        
        if w < 50:
            w = 400
        if h < 50:
            h = 200
            
        padding = 40
        chart_w = w - padding * 2
        chart_h = h - padding * 2
        
        stats = self.analyzer.get_statistics()
        items = sorted(stats['type_distribution'].items())
        
        if not items:
            canvas.create_text(w // 2, h // 2, text="暂无数据", 
                               font=FONTS['label'], fill=COLORS['text_disabled'])
            return
            
        max_count = max(v for _, v in items) if items else 1
        n = len(items)
        bar_width = chart_w / n * 0.6
        gap = chart_w / n * 0.4
        
        text_color = COLORS['text_primary']
        
        canvas.create_line(padding, padding, padding, h - padding, 
                           fill=COLORS['border'], width=1)
        canvas.create_line(padding, h - padding, w - padding, h - padding, 
                           fill=COLORS['border'], width=1)
        
        steps = 5
        for i in range(steps + 1):
            y = h - padding - (chart_h * i / steps)
            val = int(max_count * i / steps)
            canvas.create_line(padding - 5, y, padding, y, 
                               fill=COLORS['border'], width=1)
            canvas.create_text(padding - 8, y, text=str(val), anchor=tk.E,
                               font=FONTS['mono_small'], fill=COLORS['text_secondary'])
        
        colors = [COLORS['accent_blue'], COLORS['accent_green'], 
                  COLORS['accent_orange'], COLORS['accent_red'], 
                  COLORS['accent_yellow'], '#6f42c1']
        
        for i, (type_num, count) in enumerate(items):
            x0 = padding + i * (bar_width + gap) + gap / 2
            bar_h = (count / max_count) * chart_h if max_count > 0 else 0
            y0 = h - padding - bar_h
            y1 = h - padding
            
            color = colors[i % len(colors)]
            canvas.create_rectangle(x0, y0, x0 + bar_width, y1,
                                    fill=color, outline='', width=0)
            
            canvas.create_text(x0 + bar_width / 2, y0 - 8, text=str(count),
                               font=FONTS['mono_small'], fill=text_color)
            
            type_name = self.analyzer.TYPE_DESCRIPTIONS.get(type_num, f"T{type_num}")[:8]
            canvas.create_text(x0 + bar_width / 2, h - padding + 15,
                               text=type_name, font=FONTS['mono_small'], 
                               fill=COLORS['text_secondary'])
        
    def _stop_capture(self):
        """停止抓包"""
        self.is_capturing = False
        self._finish_analysis()
        
    def _finish_analysis(self):
        """完成分析"""
        self.is_capturing = False
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.status_var.set(f"● 分析完成")
        self.capture_time_var.set("抓包时长: 00:00:00")
        
        if not self.packets:
            self.empty_label.place(relx=0.5, rely=0.5, anchor='center')
            
    def _clear_results(self):
        """清空结果"""
        self.packets.clear()
        self.analyzer = ICMPAnalyzer()
        
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        self.fields_text.delete('1.0', tk.END)
        self.raw_text.delete('1.0', tk.END)
        
        self.stat_cards['total'].config(text="0")
        self.stat_cards['error'].config(text="0")
        self.stat_cards['checksum_error'].config(text="0")
        self.stat_cards['valid'].config(text="0")
        
        self.chart_canvas.delete("all")
        
        self.total_count_var.set("报文总数: 0")
        self.parsed_count_var.set("已解析: 0")
        self.status_var.set("● 已清空")
        
        self.empty_label.place(relx=0.5, rely=0.5, anchor='center')
        
    def _show_statistics(self):
        """显示统计报表窗口"""
        if not self.packets:
            messagebox.showinfo("提示", "没有可统计的数据")
            return
            
        stats = self.analyzer.get_statistics()
        
        stats_window = tk.Toplevel(self.root)
        stats_window.title("📊 统计报表 - ICMP Analyzer")
        stats_window.geometry("900x650")
        stats_window.minsize(700, 500)
        
        self.style.theme_use('darkly')
        
        main_container = ttk.Frame(stats_window, style='Card.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True)
        
        header = ttk.Frame(main_container, style='Accent.TFrame')
        header.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header, text="📊 ICMP报文分析统计报表",
                  font=FONTS['title'],
                  foreground=COLORS['text_primary']).pack(side=tk.LEFT, padx=15, pady=10)
        
        ttk.Button(header, text="💾 导出报表",
                   command=lambda: self._export_stats(stats),
                   style='Report.TButton').pack(side=tk.RIGHT, padx=10, pady=10)
        
        ttk.Button(header, text="✖ 关闭",
                   command=stats_window.destroy,
                   style='Clear.TButton').pack(side=tk.RIGHT, padx=5, pady=10)
        
        body = ttk.Frame(main_container, style='Card.TFrame')
        body.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        
        left_panel = ttk.Frame(body, style='Card.TFrame')
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        right_panel = ttk.Frame(body, style='Card.TFrame')
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        cards_frame = ttk.Frame(left_panel, style='Card.TFrame')
        cards_frame.pack(fill=tk.X, pady=(0, 10))
        
        total = stats['total_packets']
        error_count = stats['error_packets']
        valid_count = total - error_count
        error_rate = (error_count / total * 100) if total > 0 else 0
        
        query_count = sum(v for k, v in stats['type_distribution'].items()
                         if self.analyzer.is_query_message(k))
        err_type_count = sum(v for k, v in stats['type_distribution'].items()
                            if self.analyzer.is_error_message(k))
        
        cards = [
            ("📦 总报文数", str(total), COLORS['accent_blue']),
            ("✅ 有效报文", str(valid_count), COLORS['accent_green']),
            ("❌ 异常报文", str(error_count), COLORS['accent_red']),
            ("⚠ 异常率", f"{error_rate:.1f}%", COLORS['accent_orange']),
        ]
        
        for i, (label, value, color) in enumerate(cards):
            card = ttk.Frame(cards_frame, style='Card.TFrame')
            card.grid(row=0, column=i, padx=5, sticky="nsew")
            cards_frame.grid_columnconfigure(i, weight=1)
            
            ttk.Label(card, text=label, font=FONTS['small'],
                      foreground=COLORS['text_secondary']).pack(fill=tk.X, pady=(8, 2), padx=10)
            
            ttk.Label(card, text=value, font=FONTS['title'],
                      foreground=color).pack(fill=tk.X, pady=(2, 8), padx=10)
        
        chart_frame = ttk.LabelFrame(left_panel, text="📈 报文类型分布", style='Card.TFrame')
        chart_frame.pack(fill=tk.BOTH, expand=True)
        
        chart_canvas = tk.Canvas(chart_frame, bg=COLORS['bg_card'],
                                  highlightthickness=0, height=280)
        chart_canvas.pack(fill=tk.BOTH, expand=True)
        
        self._draw_bar_chart(chart_canvas, stats)
        
        right_title = ttk.Label(right_panel, text="📋 详细数据", 
                                font=FONTS['label_bold'],
                                foreground=COLORS['text_primary'])
        right_title.pack(anchor=tk.W, pady=(0, 5))
        
        detail_text = scrolledtext.ScrolledText(right_panel, wrap=tk.WORD, 
                                                font=FONTS['mono'],
                                                width=45, height=20,
                                                background=COLORS['bg_card'],
                                                foreground=COLORS['text_primary'])
        detail_text.pack(fill=tk.BOTH, expand=True)
        
        detail_report = []
        detail_report.append(f"总报文数:    {total}")
        detail_report.append(f"有效报文:    {valid_count}")
        detail_report.append(f"异常报文:    {error_count}")
        detail_report.append(f"异常率:      {error_rate:.1f}%")
        detail_report.append("")
        detail_report.append("=" * 40)
        detail_report.append("报文分类统计")
        detail_report.append("=" * 40)
        detail_report.append(f"查询报文:    {query_count}")
        detail_report.append(f"差错报文:    {err_type_count}")
        detail_report.append(f"其他报文:    {total - query_count - err_type_count}")
        detail_report.append("")
        detail_report.append("=" * 40)
        detail_report.append("类型详细分布")
        detail_report.append("=" * 40)
        
        for type_num, count in sorted(stats['type_distribution'].items()):
            percentage = stats['type_percentages'][type_num]
            type_name = self.analyzer.TYPE_DESCRIPTIONS.get(type_num, "未知类型")[:20]
            detail_report.append(f"Type {type_num:2d}: {count:4d} ({percentage:5.1f}%)")
            detail_report.append(f"  └─ {type_name}")
        
        detail_text.insert(tk.END, "\n".join(detail_report))
        detail_text.config(state=tk.DISABLED)
        
        footer = ttk.Frame(main_container, style='Card.TFrame')
        footer.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        ttk.Label(footer, text="💡 提示: 报表数据基于当前会话已分析的报文",
                  font=FONTS['small'], foreground=COLORS['text_secondary']).pack(side=tk.LEFT)
        
        import datetime
        ttk.Label(footer, text=f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                  font=FONTS['small'], foreground=COLORS['text_secondary']).pack(side=tk.RIGHT)
        
    def _draw_bar_chart(self, canvas, stats):
        """在Canvas上绘制柱状图"""
        canvas.delete("all")
        
        canvas.update_idletasks()
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        
        if w < 50:
            w = 600
        if h < 50:
            h = 280
            
        padding = 40
        chart_w = w - padding * 2
        chart_h = h - padding * 2
        
        items = sorted(stats['type_distribution'].items())
        if not items:
            canvas.create_text(w // 2, h // 2, text="暂无数据", 
                               font=FONTS['label'], fill=COLORS['text_disabled'])
            return
            
        max_count = max(v for _, v in items) if items else 1
        n = len(items)
        bar_width = chart_w / n * 0.7
        gap = chart_w / n * 0.3
        
        text_color = COLORS['text_primary']
        
        canvas.create_line(padding, padding, padding, h - padding, 
                           fill=COLORS['border'], width=1)
        canvas.create_line(padding, h - padding, w - padding, h - padding, 
                           fill=COLORS['border'], width=1)
        
        steps = 5
        for i in range(steps + 1):
            y = h - padding - (chart_h * i / steps)
            val = int(max_count * i / steps)
            canvas.create_line(padding - 5, y, padding, y, 
                               fill=COLORS['border'], width=1)
            canvas.create_text(padding - 8, y, text=str(val), anchor=tk.E,
                               font=FONTS['mono_small'], fill=COLORS['text_secondary'])
        
        colors = [COLORS['accent_blue'], COLORS['accent_green'], 
                  COLORS['accent_orange'], COLORS['accent_red'], 
                  COLORS['accent_yellow'], '#6f42c1', '#0dcaf0']
        
        for i, (type_num, count) in enumerate(items):
            x0 = padding + i * (bar_width + gap) + gap / 2
            bar_h = (count / max_count) * chart_h if max_count > 0 else 0
            y0 = h - padding - bar_h
            y1 = h - padding
            
            color = colors[i % len(colors)]
            canvas.create_rectangle(x0, y0, x0 + bar_width, y1,
                                    fill=color, outline='', width=0)
            
            canvas.create_text(x0 + bar_width / 2, y0 - 10, text=str(count),
                               font=FONTS['mono'], fill=text_color)
            
            canvas.create_text(x0 + bar_width / 2, h - padding + 12,
                               text=f"T{type_num}", font=FONTS['mono_small'], 
                               fill=COLORS['text_secondary'])
        
        canvas.create_text(padding, 15, anchor=tk.W,
                           text="报文类型 - 数量", font=FONTS['label_bold'],
                           fill=text_color)
        
    def _export_stats(self, stats):
        """导出统计报表"""
        file_path = filedialog.asksaveasfilename(
            title="导出统计报表",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if not file_path:
            return
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("ICMP报文分析统计报表\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"总报文数: {stats['total_packets']}\n")
                f.write(f"异常报文数: {stats['error_packets']}\n\n")
                f.write("报文类型分布:\n")
                f.write("-" * 60 + "\n")
                for type_num, count in sorted(stats['type_distribution'].items()):
                    percentage = stats['type_percentages'][type_num]
                    type_name = self.analyzer.TYPE_DESCRIPTIONS.get(type_num, "未知类型")
                    f.write(f"Type {type_num:2d}: {count:4d} ({percentage:5.1f}%) {type_name}\n")
            messagebox.showinfo("成功", f"报表已导出到: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")
            
    def _export_results(self):
        """导出结果"""
        if not self.packets:
            messagebox.showinfo("提示", "没有可导出的数据")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="导出结果",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("ICMP报文分析结果\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for i, packet in enumerate(self.packets, 1):
                        f.write(f"报文 #{i}\n")
                        f.write(self.analyzer.format_output(packet))
                        f.write("\n\n")
                        
                    f.write("\n" + "=" * 60 + "\n")
                    f.write("统计信息\n")
                    f.write("=" * 60 + "\n")
                    
                    stats = self.analyzer.get_statistics()
                    f.write(f"总报文数: {stats['total_packets']}\n")
                    f.write(f"异常报文数: {stats['error_packets']}\n")
                
                messagebox.showinfo("成功", f"结果已导出到: {file_path}")
                
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {e}")
    
    def _show_tooltip(self, widget, text):
        """显示悬浮提示"""
        if self.tooltip_id:
            self.root.after_cancel(self.tooltip_id)
        
        def create_tooltip():
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            
            self.tooltip = tk.Toplevel(self.root)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = ttk.Label(self.tooltip, text=text, 
                             background=COLORS['bg_highlight'],
                             foreground=COLORS['text_primary'],
                             font=FONTS['small'],
                             padding=(8, 4),
                             borderwidth=1,
                             relief=tk.SOLID)
            label.pack()
        
        self.tooltip_id = self.root.after(500, create_tooltip)
    
    def _hide_tooltip(self):
        """隐藏悬浮提示"""
        if self.tooltip_id:
            self.root.after_cancel(self.tooltip_id)
            self.tooltip_id = None
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None
    
    def _add_tooltip(self, widget, text):
        """为控件添加悬浮提示"""
        widget.bind('<Enter>', lambda e: self._show_tooltip(widget, text))
        widget.bind('<Leave>', lambda e: self._hide_tooltip())


def main():
    """主函数"""
    root = tk.Tk()
    app = ICMPAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()