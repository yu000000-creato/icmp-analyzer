"""
ICMP差错报文分析程序 - Tkinter图形化界面（ttkbootstrap美化）
提供轻量化图形化解析面板
"""

import tkinter as tk
from tkinter import scrolledtext, filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.style import Style
from ttkbootstrap.dialogs import Messagebox
from typing import Optional, List
import threading
import queue

from icmp_analyzer import ICMPAnalyzer, ICMPPacket, ICMPType
from packet_reader import (
    LivePacketReader, OfflinePacketReader, BinarySampleReader,
    create_sample_icmp_packets, get_network_interfaces
)


class ICMPAnalyzerGUI:
    """ICMP分析器图形界面"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ICMP差错报文分析程序")
        self.root.geometry("1300x850")
        
        self.style = Style()
        self.style.theme_use('darkly')
        
        self.analyzer = ICMPAnalyzer()
        
        self.packet_queue = queue.Queue()
        
        self.capture_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        
        self.packets: List[ICMPPacket] = []
        
        self._create_widgets()
        
    def _create_widgets(self):
        """创建界面组件 - VSCode风格布局"""
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_title_bar(main_frame)

        body = ttk.Frame(main_frame)
        body.pack(fill=tk.BOTH, expand=True)

        self._create_sidebar(body)

        main_area = ttk.Frame(body)
        main_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        middle_frame = ttk.Panedwindow(main_area, orient=tk.HORIZONTAL)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        left_frame = ttk.LabelFrame(middle_frame, text="  📋 报文列表  ")
        middle_frame.add(left_frame, weight=1)
        self._create_packet_list(left_frame)

        right_frame = ttk.LabelFrame(middle_frame, text="  🔍 详细信息  ")
        middle_frame.add(right_frame, weight=2)
        self._create_detail_panel(right_frame)

        self._create_status_bar(main_frame)

    def _create_title_bar(self, parent):
        """VSCode风格标题栏"""
        title_bar = ttk.Frame(parent, bootstyle="dark")
        title_bar.pack(fill=tk.X)

        ttk.Label(
            title_bar, text="🌐 ICMP 差错报文分析程序",
            font=('Microsoft YaHei', 12, 'bold'),
            bootstyle="inverse-primary"
        ).pack(side=tk.LEFT, padx=15, pady=8)

        ttk.Label(
            title_bar, text="v1.0.0",
            font=('Consolas', 9),
            bootstyle="inverse-secondary"
        ).pack(side=tk.LEFT, padx=5)

        theme_frame = ttk.Frame(title_bar)
        theme_frame.pack(side=tk.RIGHT, padx=10, pady=5)

        ttk.Label(theme_frame, text="🎨 主题:",
                  font=('Microsoft YaHei', 9),
                  bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=(0, 5))

        themes = ['darkly', 'cyborg', 'superhero', 'solar',
                  'minty', 'flatly', 'journal', 'litera', 'cosmo', 'pulse']
        self.theme_var = ttk.StringVar(value='darkly')
        theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var,
                                    values=themes, width=10, state='readonly',
                                    bootstyle="secondary")
        theme_combo.pack(side=tk.LEFT)
        theme_combo.bind('<<ComboboxSelected>>', self._on_theme_change)

    def _create_sidebar(self, parent):
        """侧边栏面板"""
        sidebar = ttk.Frame(parent, bootstyle="default", width=260)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        self.sidebar_notebook = ttk.Notebook(sidebar, bootstyle="primary")
        self.sidebar_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Separator(parent, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y)

        self._create_control_sidebar(self.sidebar_notebook)
        self._create_stats_sidebar(self.sidebar_notebook)
        self._create_tools_sidebar(self.sidebar_notebook)
        self._create_about_sidebar(self.sidebar_notebook)

    def _create_control_sidebar(self, parent):
        """控制面板侧边栏"""
        frame = ttk.Frame(parent)
        parent.add(frame, text="⚙ 控制")

        canvas = tk.Canvas(frame, highlightthickness=0, bg=self.style.lookup('TFrame', 'background'))
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable = ttk.Frame(canvas)

        scrollable.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        section = ttk.LabelFrame(scrollable, text="  抓包模式  ")
        section.pack(fill=tk.X, padx=10, pady=10)

        self.mode_var = ttk.StringVar(value="offline")

        ttk.Radiobutton(section, text="📁 离线文件", variable=self.mode_var,
                        value="offline", command=self._on_mode_change,
                        bootstyle="success-button").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(section, text="📡 实时抓包", variable=self.mode_var,
                        value="live", command=self._on_mode_change,
                        bootstyle="primary-button").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(section, text="🧪 测试样本", variable=self.mode_var,
                        value="sample", command=self._on_mode_change,
                        bootstyle="info-button").pack(anchor=tk.W, pady=2)

        section2 = ttk.LabelFrame(scrollable, text="  文件路径  ")
        section2.pack(fill=tk.X, padx=10, pady=5)

        self.file_path_var = ttk.StringVar()
        self.file_entry = ttk.Entry(section2, textvariable=self.file_path_var,
                                     bootstyle=SUCCESS)
        self.file_entry.pack(fill=tk.X, pady=(0, 5))

        self.browse_button = ttk.Button(section2, text="📂 浏览文件", command=self._browse_file,
                                        bootstyle=SECONDARY)
        self.browse_button.pack(fill=tk.X)

        section3 = ttk.LabelFrame(scrollable, text="  网络接口  ")
        section3.pack(fill=tk.X, padx=10, pady=5)

        self.interface_var = ttk.StringVar()
        self.interface_combo = ttk.Combobox(section3, textvariable=self.interface_var,
                                             bootstyle=PRIMARY, state='readonly')
        self.interface_combo['values'] = get_network_interfaces()
        if self.interface_combo['values']:
            self.interface_combo.current(0)
        self.interface_combo.pack(fill=tk.X, pady=2)

        ttk.Label(section3, text="抓包数量:",
                  font=('Microsoft YaHei', 9)).pack(anchor=tk.W, pady=(5, 0))
        self.count_var = ttk.StringVar(value="0")
        ttk.Entry(section3, textvariable=self.count_var, bootstyle=INFO).pack(fill=tk.X, pady=2)

        ttk.Label(section3, text="(0=无限制)",
                  font=('Microsoft YaHei', 8), bootstyle="secondary").pack(anchor=tk.W)

        ttk.Label(section3, text="超时时间(秒):",
                  font=('Microsoft YaHei', 9)).pack(anchor=tk.W, pady=(5, 0))
        self.timeout_var = ttk.StringVar(value="10")
        ttk.Entry(section3, textvariable=self.timeout_var, bootstyle=INFO).pack(fill=tk.X, pady=2)

        section4 = ttk.LabelFrame(scrollable, text="  操作  ")
        section4.pack(fill=tk.X, padx=10, pady=5)

        self.start_btn = ttk.Button(section4, text="▶ 开始分析",
                                     command=self._start_analysis, bootstyle=SUCCESS)
        self.start_btn.pack(fill=tk.X, pady=2)

        self.stop_btn = ttk.Button(section4, text="⏹ 停止",
                                    command=self._stop_capture, bootstyle=DANGER,
                                    state=DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=2)

        ttk.Button(section4, text="🗑 清空结果",
                   command=self._clear_results, bootstyle=SECONDARY).pack(fill=tk.X, pady=2)

        ttk.Button(section4, text="📊 生成报表",
                   command=self._show_statistics, bootstyle=INFO).pack(fill=tk.X, pady=2)

        ttk.Button(section4, text="💾 导出结果",
                   command=self._export_results, bootstyle=WARNING).pack(fill=tk.X, pady=2)

        self._on_mode_change()

    def _create_stats_sidebar(self, parent):
        """统计侧边栏"""
        frame = ttk.Frame(parent)
        parent.add(frame, text="📊 统计")

        info_label = ttk.Label(frame, text="完成分析后\n点击\"生成报表\"\n查看详细统计",
                                font=('Microsoft YaHei', 10),
                                bootstyle="secondary",
                                justify=tk.CENTER)
        info_label.pack(expand=True, padx=20, pady=20)

        ttk.Button(frame, text="📊 立即生成报表",
                   command=self._show_statistics, bootstyle=INFO).pack(pady=10)

    def _create_tools_sidebar(self, parent):
        """工具侧边栏"""
        frame = ttk.Frame(parent)
        parent.add(frame, text="🔧 工具")

        tools = [
            ("🔄 刷新接口列表", self._refresh_interfaces),
            ("📋 复制当前报文", self._copy_current),
            ("🔍 报文过滤", self._filter_packets),
            ("📤 导出为JSON", self._export_json),
            ("📥 导入pcap", self._import_pcap),
        ]

        for text, cmd in tools:
            ttk.Button(frame, text=text, command=cmd,
                       bootstyle=SECONDARY).pack(fill=tk.X, padx=10, pady=5)

    def _create_about_sidebar(self, parent):
        """关于侧边栏"""
        frame = ttk.Frame(parent)
        parent.add(frame, text="ℹ 关于")

        about_text = """
🌐 ICMP 差错报文分析程序

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
                                                 font=('Microsoft YaHei', 10),
                                                 height=20)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, about_text)
        text_widget.config(state=tk.DISABLED)

    def _refresh_interfaces(self):
        """刷新接口列表"""
        interfaces = get_network_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.current(0)
        Messagebox.showinfo("提示", f"已刷新，共 {len(interfaces)} 个接口")

    def _copy_current(self):
        """复制当前报文"""
        if not self.packets:
            Messagebox.showwarning("提示", "没有可复制的报文")
            return
        selection = self.packet_tree.selection()
        if not selection:
            Messagebox.showwarning("提示", "请先选择报文")
            return
        item = selection[0]
        index = self.packet_tree.index(item)
        if index < len(self.packets):
            packet = self.packets[index]
            self.root.clipboard_clear()
            self.root.clipboard_append(self.analyzer.format_output(packet))
            Messagebox.showinfo("成功", "已复制到剪贴板")

    def _filter_packets(self):
        """报文过滤"""
        Messagebox.showinfo("提示", "过滤功能开发中")

    def _export_json(self):
        """导出为JSON"""
        if not self.packets:
            Messagebox.showwarning("提示", "没有可导出的数据")
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
            Messagebox.showinfo("成功", f"已导出到: {file_path}")
        except Exception as e:
            Messagebox.showerror("错误", f"导出失败: {e}")

    def _import_pcap(self):
        """导入pcap"""
        file_path = filedialog.askopenfilename(
            title="选择pcap文件",
            filetypes=[("PCAP文件", "*.pcap"), ("所有文件", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.mode_var.set("offline")
            self._on_mode_change()
            self._start_analysis()

    def _on_theme_change(self, event):
        """主题切换"""
        theme = self.theme_var.get()
        self.style.theme_use(theme)

    def _create_packet_list(self, parent):
        """创建报文列表"""
        columns = ('序号', '类型', '代码', '校验和', '分类', '描述')
        self.packet_tree = ttk.Treeview(parent, columns=columns, show='headings', 
                                         height=22, bootstyle=INFO)
        
        style = ttk.Style()
        style.configure('Treeview', font=('Consolas', 10))
        style.configure('Treeview.Heading', font=('Microsoft YaHei', 10, 'bold'))
        
        self.packet_tree.heading('序号', text='序号')
        self.packet_tree.heading('类型', text='类型')
        self.packet_tree.heading('代码', text='代码')
        self.packet_tree.heading('校验和', text='校验和')
        self.packet_tree.heading('分类', text='分类')
        self.packet_tree.heading('描述', text='描述')
        
        self.packet_tree.column('序号', width=60, anchor='center')
        self.packet_tree.column('类型', width=100, anchor='center')
        self.packet_tree.column('代码', width=60, anchor='center')
        self.packet_tree.column('校验和', width=100, anchor='center')
        self.packet_tree.column('分类', width=90, anchor='center')
        self.packet_tree.column('描述', width=220, anchor='w')
        
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scrollbar.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_tree.bind('<<TreeviewSelect>>', self._on_packet_select)
        
    def _create_detail_panel(self, parent):
        """创建详细信息面板"""
        notebook = ttk.Notebook(parent, bootstyle=SUCCESS)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        fields_frame = ttk.Frame(notebook)
        notebook.add(fields_frame, text="字段解析")
        self._create_fields_panel(fields_frame)
        
        raw_frame = ttk.Frame(notebook)
        notebook.add(raw_frame, text="原始数据")
        self._create_raw_panel(raw_frame)
        
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="统计信息")
        self._create_stats_panel(stats_frame)
        
    def _create_fields_panel(self, parent):
        """创建字段解析面板"""
        self.fields_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Consolas', 10),
                                        height=25)
        self.fields_text.pack(fill=tk.BOTH, expand=True)
        
    def _create_raw_panel(self, parent):
        """创建原始数据面板"""
        self.raw_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Consolas', 10),
                                     height=25)
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        
    def _create_stats_panel(self, parent):
        """创建统计面板"""
        self.stats_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=('Consolas', 10),
                                       height=25)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
    def _create_status_bar(self, parent):
        """创建状态栏"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_var = ttk.StringVar(value="就绪")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, 
                                  font=('Microsoft YaHei', 10))
        status_label.pack(side=tk.LEFT, padx=10)
        
        self.count_label = ttk.Label(status_frame, text="已解析: 0 个报文",
                                      font=('Microsoft YaHei', 10))
        self.count_label.pack(side=tk.RIGHT, padx=10)
        
    def _on_mode_change(self):
        """模式切换响应"""
        mode = self.mode_var.get()
        
        if mode == "live":
            self.file_entry.config(state=DISABLED, bootstyle='secondary')
            self.browse_button.config(state=DISABLED, bootstyle='secondary-outline')
            self.interface_combo.config(state=NORMAL, bootstyle='primary')
        elif mode == "offline":
            self.file_entry.config(state=NORMAL, bootstyle='success')
            self.browse_button.config(state=NORMAL, bootstyle='secondary')
            self.interface_combo.config(state=DISABLED, bootstyle='secondary')
        else:
            self.file_entry.config(state=DISABLED, bootstyle='secondary')
            self.browse_button.config(state=DISABLED, bootstyle='secondary-outline')
            self.interface_combo.config(state=DISABLED, bootstyle='secondary')
            
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
        
        self.analyzer = ICMPAnalyzer()
        self.packets.clear()
        
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        self.status_var.set("正在分析...")
        
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
            Messagebox.showerror("错误", f"分析失败: {e}")
            self._finish_analysis()
            
    def _analyze_offline(self):
        """分析离线文件"""
        file_path = self.file_path_var.get()
        
        if not file_path:
            Messagebox.showwarning("警告", "请选择文件路径")
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
            Messagebox.showwarning("警告", "请输入有效的数值")
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
                    Messagebox.showerror("错误", item[1])
                    self._finish_analysis()
                    return
                else:
                    i, packet = item
                    self._add_packet_to_list(i, packet)
                    
        except queue.Empty:
            pass
            
        if self.is_capturing:
            self.root.after(100, self._process_queue)
            
    def _add_packet_to_list(self, index: int, packet: ICMPPacket):
        """添加报文到列表"""
        if self.analyzer.is_query_message(packet.header.type):
            category = "查询报文"
        elif self.analyzer.is_error_message(packet.header.type):
            category = "差错报文"
        else:
            category = "其他"
            
        desc = packet.description.split('\n')[0][:35]
        
        self.packet_tree.insert('', 'end', values=(
            index,
            f"{packet.header.type} ({self.analyzer.TYPE_DESCRIPTIONS.get(packet.header.type, '未知')[:12]})",
            packet.header.code,
            f"0x{packet.header.checksum:04X}",
            category,
            desc
        ))
        
        self.count_label.config(text=f"已解析: {len(self.packets)} 个报文")
        
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
            
    def _display_packet_details(self, packet: ICMPPacket):
        """显示报文详细信息"""
        self.fields_text.delete('1.0', tk.END)
        self.fields_text.insert(tk.END, self.analyzer.format_output(packet))
        
        self.raw_text.delete('1.0', tk.END)
        self.raw_text.insert(tk.END, "=== 原始数据 (十六进制) ===\n")
        raw_hex = packet.raw_data.hex()
        for i in range(0, len(raw_hex), 32):
            line = raw_hex[i:i+32]
            offset = i // 2
            self.raw_text.insert(tk.END, f"{offset:04X}  {line}\n")
            
    def _stop_capture(self):
        """停止抓包"""
        self.is_capturing = False
        self.status_var.set("已停止")
        self._finish_analysis()
        
    def _finish_analysis(self):
        """完成分析"""
        self.is_capturing = False
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.status_var.set(f"分析完成，共 {len(self.packets)} 个报文")
        
        self._update_statistics()
        
    def _clear_results(self):
        """清空结果"""
        self.packets.clear()
        self.analyzer = ICMPAnalyzer()
        
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        self.fields_text.delete('1.0', tk.END)
        self.raw_text.delete('1.0', tk.END)
        self.stats_text.delete('1.0', tk.END)
        
        self.count_label.config(text="已解析: 0 个报文")
        self.status_var.set("已清空")
        
    def _update_statistics(self):
        """更新统计信息"""
        self.stats_text.delete('1.0', tk.END)
        
        stats = self.analyzer.get_statistics()
        
        self.stats_text.insert(tk.END, "=" * 50 + "\n")
        self.stats_text.insert(tk.END, "ICMP报文统计报表\n")
        self.stats_text.insert(tk.END, "=" * 50 + "\n\n")
        
        self.stats_text.insert(tk.END, f"总报文数: {stats['total_packets']}\n")
        self.stats_text.insert(tk.END, f"异常报文数: {stats['error_packets']}\n\n")
        
        self.stats_text.insert(tk.END, "报文类型分布:\n")
        self.stats_text.insert(tk.END, "-" * 50 + "\n")
        
        for type_num, count in sorted(stats['type_distribution'].items()):
            percentage = stats['type_percentages'][type_num]
            type_name = self.analyzer.TYPE_DESCRIPTIONS.get(type_num, "未知类型")
            self.stats_text.insert(tk.END, 
                f"  Type {type_num:2d} ({type_name[:20]:20s}): {count:4d} ({percentage:5.1f}%)\n")
            
    def _show_statistics(self):
        """显示统计报表窗口（VSCode风格）"""
        if not self.packets:
            Messagebox.showinfo("提示", "没有可统计的数据")
            return

        stats = self.analyzer.get_statistics()

        stats_window = ttk.Toplevel(self.root)
        stats_window.title("📊 统计报表 - ICMP Analyzer")
        stats_window.geometry("900x650")
        stats_window.resizable(True, True)
        stats_window.minsize(700, 500)

        main_container = ttk.Frame(stats_window)
        main_container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(main_container, bootstyle="dark")
        header.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header, text="📊 ICMP 报文分析统计报表",
            font=('Microsoft YaHei', 14, 'bold'),
            bootstyle="inverse-primary"
        ).pack(side=tk.LEFT, padx=15, pady=10)

        ttk.Button(
            header, text="💾 导出报表", bootstyle=SUCCESS,
            command=lambda: self._export_stats(stats)
        ).pack(side=tk.RIGHT, padx=10, pady=10)

        ttk.Button(
            header, text="✖ 关闭", bootstyle=SECONDARY,
            command=stats_window.destroy
        ).pack(side=tk.RIGHT, padx=5, pady=10)

        body = ttk.Frame(main_container)
        body.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))

        left_panel = ttk.Frame(body)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        right_panel = ttk.Frame(body)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))

        cards_frame = ttk.Frame(left_panel)
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
            ("📦 总报文数", str(total), "primary"),
            ("✅ 有效报文", str(valid_count), "success"),
            ("❌ 异常报文", str(error_count), "danger"),
            ("⚠ 异常率", f"{error_rate:.1f}%", "warning"),
        ]

        for i, (label, value, style) in enumerate(cards):
            card = ttk.Frame(cards_frame, bootstyle=style, relief="ridge", borderwidth=1)
            card.grid(row=0, column=i, padx=5, sticky="nsew")
            cards_frame.grid_columnconfigure(i, weight=1, uniform="card")

            ttk.Label(
                card, text=label, font=('Microsoft YaHei', 9),
                bootstyle=f"inverse-{style}"
            ).pack(fill=tk.X, pady=(8, 2), padx=10)

            ttk.Label(
                card, text=value, font=('Microsoft YaHei', 18, 'bold'),
                bootstyle=f"inverse-{style}"
            ).pack(fill=tk.X, pady=(2, 8), padx=10)

        chart_frame = ttk.LabelFrame(left_panel, text="📈 报文类型分布")
        chart_frame.pack(fill=tk.BOTH, expand=True)

        chart_canvas = tk.Canvas(chart_frame, bg=self.style.lookup('TFrame', 'background'),
                                  highlightthickness=0, height=280)
        chart_canvas.pack(fill=tk.BOTH, expand=True)

        self._draw_bar_chart(chart_canvas, stats)

        right_title = ttk.Label(right_panel, text="📋 详细数据", font=('Microsoft YaHei', 11, 'bold'))
        right_title.pack(anchor=tk.W, pady=(0, 5))

        detail_text = scrolledtext.ScrolledText(
            right_panel, wrap=tk.WORD, font=('Consolas', 10),
            width=45, height=20
        )
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
            bar = "█" * int(percentage / 2)
            detail_report.append(
                f"Type {type_num:2d}: {count:4d} ({percentage:5.1f}%)"
            )
            detail_report.append(f"  └─ {type_name}")
            detail_report.append(f"     {bar}")

        detail_text.insert(tk.END, "\n".join(detail_report))
        detail_text.config(state=tk.DISABLED)

        footer = ttk.Frame(main_container)
        footer.pack(fill=tk.X, padx=15, pady=(0, 10))

        ttk.Label(
            footer, text="💡 提示: 报表数据基于当前会话已分析的报文",
            font=('Microsoft YaHei', 9), bootstyle="secondary"
        ).pack(side=tk.LEFT)

        ttk.Label(
            footer, text=f"生成时间: {tk.Tk.tk.call('clock', 'format', 'default', 'default')}",
            font=('Microsoft YaHei', 9), bootstyle="secondary"
        ).pack(side=tk.RIGHT)

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
            canvas.create_text(w // 2, h // 2, text="暂无数据", font=('Microsoft YaHei', 12))
            return

        max_count = max(v for _, v in items) if items else 1
        n = len(items)
        bar_width = chart_w / n * 0.7
        gap = chart_w / n * 0.3

        bg_color = self.style.lookup('TFrame', 'background')
        text_color = self.style.lookup('TLabel', 'foreground')
        if not text_color:
            text_color = '#CCCCCC'

        canvas.create_line(padding, padding, padding, h - padding, fill=text_color, width=1)
        canvas.create_line(padding, h - padding, w - padding, h - padding, fill=text_color, width=1)

        steps = 5
        for i in range(steps + 1):
            y = h - padding - (chart_h * i / steps)
            val = int(max_count * i / steps)
            canvas.create_line(padding - 5, y, padding, y, fill=text_color, width=1)
            canvas.create_text(padding - 8, y, text=str(val), anchor=tk.E,
                               font=('Consolas', 8), fill=text_color)

        colors = ['#0d6efd', '#198754', '#dc3545', '#ffc107', '#0dcaf0',
                  '#6f42c1', '#fd7e14', '#20c997', '#d63384', '#6c757d']

        for i, (type_num, count) in enumerate(items):
            x0 = padding + i * (bar_width + gap) + gap / 2
            bar_h = (count / max_count) * chart_h if max_count > 0 else 0
            y0 = h - padding - bar_h
            y1 = h - padding

            color = colors[i % len(colors)]
            canvas.create_rectangle(x0, y0, x0 + bar_width, y1,
                                    fill=color, outline=color, width=1)

            canvas.create_text(x0 + bar_width / 2, y0 - 10, text=str(count),
                               font=('Consolas', 9, 'bold'), fill=text_color)

            canvas.create_text(x0 + bar_width / 2, h - padding + 12,
                               text=f"T{type_num}", font=('Consolas', 9), fill=text_color)

        title = canvas.create_text(padding, 15, anchor=tk.W,
                                   text="报文类型 - 数量", font=('Microsoft YaHei', 10, 'bold'),
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
                    bar = "█" * int(percentage / 2)
                    f.write(f"Type {type_num:2d}: {count:4d} ({percentage:5.1f}%) {bar}\n")
            Messagebox.showinfo("成功", f"报表已导出到: {file_path}")
        except Exception as e:
            Messagebox.showerror("错误", f"导出失败: {e}")
        
    def _export_results(self):
        """导出结果"""
        if not self.packets:
            Messagebox.showinfo("提示", "没有可导出的数据")
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
                
                Messagebox.showinfo("成功", f"结果已导出到: {file_path}")
                
            except Exception as e:
                Messagebox.showerror("错误", f"导出失败: {e}")


def main():
    """主函数"""
    root = tk.Tk()
    app = ICMPAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()