import sys
import os
import socket
import threading
import subprocess
import time
import re
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import queue
import platform
import psutil
import netifaces
from collections import defaultdict

class CyberShieldNIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Network Packet Filter v14.0")
        self.root.geometry("1200x800")
        self.root.configure(bg='black')
        
        # Threat counters
        self.threat_counts = {
            'DDOS': 0,
            'PortScan': 0,
            'DOS': 0,
            'UDPFlood': 0,
            'HTTPFlood': 0,
            'HTTPSFlood': 0,
            'Suspicious': 0
        }
        
        # Network monitoring variables
        self.monitoring_ip = None
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.port_scan_threshold = 10  # Ports scanned within time window
        self.port_scan_window = 5      # Seconds
        self.port_scan_tracker = defaultdict(list)
        
        # Packet analysis variables
        self.packet_stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'Other': 0
        }
        
        # Create GUI
        self.create_gui()
        
        # Command queue for terminal output
        self.command_queue = queue.Queue()
        
        # Start the GUI update loop
        self.update_gui()
    
    def create_gui(self):
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', background='black', foreground='#00FF00', 
                       fieldbackground='black', insertcolor='#00FF00')
        style.configure('TFrame', background='black')
        style.configure('TLabel', background='black', foreground='#00FF00')
        style.configure('TButton', background='black', foreground='#00FF00', 
                       bordercolor='#00FF00', lightcolor='black', darkcolor='black')
        style.configure('TEntry', fieldbackground='black', foreground='#00FF00')
        style.configure('TCombobox', fieldbackground='black', foreground='#00FF00')
        style.configure('TNotebook', background='black', bordercolor='#00FF00')
        style.configure('TNotebook.Tab', background='black', foreground='#00FF00', 
                       lightcolor='black', bordercolor='#00FF00')
        style.map('TNotebook.Tab', background=[('selected', '#003300')])
        style.configure('Treeview', background='black', foreground='#00FF00', 
                        fieldbackground='black')
        style.configure('Treeview.Heading', background='black', foreground='#00FF00')
        style.map('Treeview', background=[('selected', '#003300')])
        
        # Menu bar
        self.menu_bar = tk.Menu(self.root, bg='black', fg='#00FF00', 
                               activebackground='#003300', activeforeground='#00FF00')
        
        # File menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='#00FF00')
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Logs", command=self.save_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='#00FF00')
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        tools_menu.add_command(label="Threat Map", command=self.open_threat_map)
        self.menu_bar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='#00FF00')
        view_menu.add_command(label="Dark Mode", command=lambda: self.set_theme('dark'))
        view_menu.add_command(label="Light Mode", command=lambda: self.set_theme('light'))
        self.menu_bar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(self.menu_bar, tearoff=0, bg='black', fg='#00FF00')
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=self.menu_bar)
        
        # Main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Controls and stats
        self.left_panel = ttk.Frame(self.main_frame, width=300)
        self.left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(self.left_panel, text="Monitoring Controls")
        control_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(control_frame, text="Target IP:").pack(anchor=tk.W)
        self.ip_entry = ttk.Entry(control_frame)
        self.ip_entry.pack(fill=tk.X, pady=2)
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                   command=self.start_monitoring)
        self.start_btn.pack(fill=tk.X, pady=2)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", 
                                  command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=2)
        
        # Network stats
        stats_frame = ttk.LabelFrame(self.left_panel, text="Network Statistics")
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_tree = ttk.Treeview(stats_frame, columns=('Value'), show='tree', height=5)
        self.stats_tree.heading('#0', text='Protocol')
        self.stats_tree.heading('Value', text='Count')
        self.stats_tree.column('#0', width=100)
        self.stats_tree.column('Value', width=50)
        self.stats_tree.pack(fill=tk.X)
        
        # Threat stats
        threat_frame = ttk.LabelFrame(self.left_panel, text="Threat Detection")
        threat_frame.pack(fill=tk.X, pady=5)
        
        self.threat_tree = ttk.Treeview(threat_frame, columns=('Count'), show='tree', height=7)
        self.threat_tree.heading('#0', text='Threat Type')
        self.threat_tree.heading('Count', text='Count')
        self.threat_tree.column('#0', width=120)
        self.threat_tree.column('Count', width=50)
        self.threat_tree.pack(fill=tk.X)
        
        # Right panel - Main content
        self.right_panel = ttk.Frame(self.main_frame)
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text='Dashboard')
        
        # Log tab
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_tab, text='Logs')
        
        self.log_text = scrolledtext.ScrolledText(
            self.log_tab, wrap=tk.WORD, width=80, height=25,
            bg='black', fg='#00FF00', insertbackground='#00FF00'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Terminal tab
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text='Terminal')
        
        self.terminal_text = scrolledtext.ScrolledText(
            self.terminal_tab, wrap=tk.WORD, width=80, height=25,
            bg='black', fg='#00FF00', insertbackground='#00FF00'
        )
        self.terminal_text.pack(fill=tk.BOTH, expand=True)
        
        self.cmd_entry = ttk.Entry(self.terminal_tab)
        self.cmd_entry.pack(fill=tk.X, pady=5)
        self.cmd_entry.bind('<Return>', self.execute_command)
        
        # Initialize stats and threat trees
        self.update_stats()
        self.update_threat_counts()
        
        # Add welcome message
        self.log("CyberShield NIDS initialized. Ready to monitor network threats.")
        self.terminal_output("Accurate Terminal - Type 'help' for available commands\n")
    
    def update_gui(self):
        # Process any pending commands in the queue
        while not self.command_queue.empty():
            cmd, output = self.command_queue.get()
            self.terminal_output(f"> {cmd}\n{output}\n")
        
        # Update stats periodically
        self.update_stats()
        self.update_threat_counts()
        
        # Schedule next update
        self.root.after(1000, self.update_gui)
    
    def update_stats(self):
        # Clear existing items
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)
        
        # Add current stats
        for proto, count in self.packet_stats.items():
            self.stats_tree.insert('', 'end', text=proto, values=(count,))
    
    def update_threat_counts(self):
        # Clear existing items
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        
        # Add current threat counts
        for threat, count in self.threat_counts.items():
            self.threat_tree.insert('', 'end', text=threat, values=(count,))
    
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def terminal_output(self, message):
        self.terminal_text.insert(tk.END, message)
        self.terminal_text.see(tk.END)
    
    def start_monitoring(self):
        ip = self.ip_entry.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return
        
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        self.monitoring_ip = ip
        self.is_monitoring = True
        
        # Reset counters
        self.packet_count = 0
        self.packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.port_scan_tracker.clear()
        
        # Start sniffer thread
        self.sniffer_thread = threading.Thread(
            target=self.sniff_traffic,
            args=(ip,),
            daemon=True
        )
        self.sniffer_thread.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self.log(f"Started monitoring traffic for IP: {ip}")
    
    def stop_monitoring(self):
        self.is_monitoring = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self.log(f"Stopped monitoring traffic for IP: {self.monitoring_ip}")
        self.monitoring_ip = None
    
    def sniff_traffic(self, target_ip):
        # Filter to capture traffic to/from the target IP
        filter_str = f"host {target_ip}"
        
        try:
            sniff(
                filter=filter_str,
                prn=self.analyze_packet,
                store=0,
                stop_filter=lambda x: not self.is_monitoring
            )
        except Exception as e:
            self.log(f"Sniffing error: {str(e)}")
    
    def analyze_packet(self, packet):
        if not self.is_monitoring:
            return
        
        self.packet_count += 1
        
        # Update protocol stats
        if IP in packet:
            if TCP in packet:
                self.packet_stats['TCP'] += 1
                self.detect_tcp_threats(packet)
            elif UDP in packet:
                self.packet_stats['UDP'] += 1
                self.detect_udp_threats(packet)
            elif ICMP in packet:
                self.packet_stats['ICMP'] += 1
                self.detect_icmp_threats(packet)
            else:
                self.packet_stats['Other'] += 1
        
        # Detect port scanning
        self.detect_port_scan(packet)
    
    def detect_tcp_threats(self, packet):
        # Detect SYN flood (potential DOS)
        if packet[TCP].flags == 'S':  # SYN flag only
            src_ip = packet[IP].src
            current_time = time.time()
            
            # Track SYN packets per source IP
            if not hasattr(self, 'syn_tracker'):
                self.syn_tracker = defaultdict(list)
            
            self.syn_tracker[src_ip].append(current_time)
            
            # Check if we've seen too many SYNs from this IP recently
            window_start = current_time - 1  # 1 second window
            syn_count = sum(1 for t in self.syn_tracker[src_ip] if t >= window_start)
            
            if syn_count > 50:  # Threshold for SYN flood
                self.threat_counts['DOS'] += 1
                self.log(f"Potential SYN Flood (DOS) detected from {src_ip} - {syn_count} SYN packets in 1 second")
        
        # Detect HTTP flood
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            if not hasattr(self, 'http_tracker'):
                self.http_tracker = defaultdict(int)
                self.last_http_check = time.time()
            
            src_ip = packet[IP].src
            self.http_tracker[src_ip] += 1
            
            # Check every 5 seconds
            if time.time() - self.last_http_check > 5:
                for ip, count in self.http_tracker.items():
                    if count > 100:  # 100 HTTP requests in 5 seconds
                        self.threat_counts['HTTPFlood'] += 1
                        self.log(f"Potential HTTP Flood detected from {ip} - {count} requests in 5 seconds")
                
                # Reset counters
                self.http_tracker.clear()
                self.last_http_check = time.time()
        
        # Detect HTTPS flood (similar to HTTP)
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            if not hasattr(self, 'https_tracker'):
                self.https_tracker = defaultdict(int)
                self.last_https_check = time.time()
            
            src_ip = packet[IP].src
            self.https_tracker[src_ip] += 1
            
            if time.time() - self.last_https_check > 5:
                for ip, count in self.https_tracker.items():
                    if count > 100:
                        self.threat_counts['HTTPSFlood'] += 1
                        self.log(f"Potential HTTPS Flood detected from {ip} - {count} requests in 5 seconds")
                
                self.https_tracker.clear()
                self.last_https_check = time.time()
    
    def detect_udp_threats(self, packet):
        # Detect UDP flood
        if not hasattr(self, 'udp_tracker'):
            self.udp_tracker = defaultdict(int)
            self.last_udp_check = time.time()
        
        src_ip = packet[IP].src
        self.udp_tracker[src_ip] += 1
        
        if time.time() - self.last_udp_check > 1:  # Check every second
            for ip, count in self.udp_tracker.items():
                if count > 100:  # 100 UDP packets in 1 second
                    self.threat_counts['UDPFlood'] += 1
                    self.log(f"Potential UDP Flood detected from {ip} - {count} packets in 1 second")
            
            self.udp_tracker.clear()
            self.last_udp_check = time.time()
    
    def detect_icmp_threats(self, packet):
        # Detect ICMP flood (Ping flood)
        if not hasattr(self, 'icmp_tracker'):
            self.icmp_tracker = defaultdict(int)
            self.last_icmp_check = time.time()
        
        src_ip = packet[IP].src
        self.icmp_tracker[src_ip] += 1
        
        if time.time() - self.last_icmp_check > 1:
            for ip, count in self.icmp_tracker.items():
                if count > 50:  # 50 ICMP packets in 1 second
                    self.threat_counts['DOS'] += 1
                    self.log(f"Potential ICMP Flood (Ping Flood) detected from {ip} - {count} packets in 1 second")
            
            self.icmp_tracker.clear()
            self.last_icmp_check = time.time()
    
    def detect_port_scan(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            current_time = time.time()
            
            # Add this port attempt to our tracker
            self.port_scan_tracker[src_ip].append((dst_port, current_time))
            
            # Clean up old entries
            window_start = current_time - self.port_scan_window
            self.port_scan_tracker[src_ip] = [
                (port, t) for port, t in self.port_scan_tracker[src_ip] 
                if t >= window_start
            ]
            
            # Count unique ports scanned in the time window
            unique_ports = len(set(
                port for port, t in self.port_scan_tracker[src_ip]
            ))
            
            if unique_ports >= self.port_scan_threshold:
                self.threat_counts['PortScan'] += 1
                self.log(f"Potential Port Scan detected from {src_ip} - {unique_ports} unique ports scanned in {self.port_scan_window} seconds")
                
                # Reset tracker for this IP to avoid repeated alerts
                self.port_scan_tracker[src_ip].clear()
    
    def execute_command(self, event):
        cmd = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        
        if not cmd:
            return
        
        # Process command
        output = self.process_command(cmd)
        
        # Add to queue for GUI thread to handle
        self.command_queue.put((cmd, output))
    
    def process_command(self, cmd):
        try:
            # Basic commands
            if cmd.lower() == 'help':
                return self.get_help_text()
            elif cmd.lower().startswith('ping '):
                return self.run_ping(cmd[5:])
            elif cmd.lower() == 'netstat':
                return self.run_netstat()
            elif cmd.lower() in ['ifconfig', 'ipconfig']:
                return self.run_ifconfig()
            elif cmd.lower() == 'ifconfig /all':
                return self.run_ifconfig(all_info=True)
            elif cmd.lower() == 'netsh wlan show network mode=bssid':
                return self.run_wlan_scan()
            elif cmd.lower().startswith('net '):
                return self.run_net_command(cmd[4:])
            else:
                return f"Unknown command: {cmd}\nType 'help' for available commands"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def get_help_text(self):
        help_text = """Available Commands:
help                 - Show this help message
ping <IP>            - Ping a network host
netstat              - Show network statistics
ifconfig / ipconfig  - Show network interface information
ifconfig /all        - Show detailed network information
netsh wlan show network mode=bssid - Show wireless networks
net <command>        - Run NET commands (see below)

NET Commands:
NET ACCOUNTS         - View account policies
NET COMPUTER         - Add/remove computers from domain
NET CONFIG           - Show server configuration
NET CONTINUE         - Resume paused service
NET FILE             - Show open shared files
NET GROUP            - Manage global groups
NET HELP             - Show NET command help
NET LOCALGROUP       - Manage local groups
NET PAUSE            - Pause a service
NET SESSION          - List/terminate sessions
NET SHARE            - Manage shared resources
NET START            - Start a service
NET STATISTICS       - Show workstation/server stats
NET STOP             - Stop a service
NET TIME             - Sync with time server
NET USE              - Connect/disconnect shares
NET USER             - Manage user accounts
NET VIEW             - Show network resources
"""
        return help_text
    
    def run_ping(self, ip):
        if not self.validate_ip(ip):
            return "Invalid IP address format"
        
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        count = '4'
        
        try:
            output = subprocess.check_output(
                ['ping', param, count, ip],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def run_netstat(self):
        try:
            output = subprocess.check_output(
                ['netstat', '-ano'] if platform.system().lower() == 'windows' else ['netstat', '-tulnp'],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def run_ifconfig(self, all_info=False):
        if platform.system().lower() == 'windows':
            cmd = ['ipconfig', '/all'] if all_info else ['ipconfig']
        else:
            cmd = ['ifconfig', '-a'] if all_info else ['ifconfig']
        
        try:
            output = subprocess.check_output(
                cmd,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def run_wlan_scan(self):
        if platform.system().lower() != 'windows':
            return "This command is only available on Windows"
        
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'network', 'mode=bssid'],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def run_net_command(self, cmd):
        try:
            output = subprocess.check_output(
                ['net'] + cmd.split(),
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            return output
        except subprocess.CalledProcessError as e:
            return e.output
    
    def validate_ip(self, ip):
        pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not pattern.match(ip):
            return False
        
        octets = ip.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False
        
        return True
    
    def new_session(self):
        self.stop_monitoring()
        self.log_text.delete(1.0, tk.END)
        self.terminal_text.delete(1.0, tk.END)
        self.log("New session started")
        self.terminal_output("CyberShield Terminal - Type 'help' for available commands\n")
    
    def save_logs(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log(f"Logs saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def open_network_scanner(self):
        messagebox.showinfo("Info", "Network Scanner feature will be implemented in a future version")
    
    def open_packet_analyzer(self):
        messagebox.showinfo("Info", "Packet Analyzer feature will be implemented in a future version")
    
    def open_threat_map(self):
        messagebox.showinfo("Info", "Threat Map feature will be implemented in a future version")
    
    def set_theme(self, theme):
        if theme == 'dark':
            self.log_text.configure(bg='black', fg='#00FF00', insertbackground='#00FF00')
            self.terminal_text.configure(bg='black', fg='#00FF00', insertbackground='#00FF00')
        else:
            self.log_text.configure(bg='white', fg='black', insertbackground='black')
            self.terminal_text.configure(bg='white', fg='black', insertbackground='black')
    
    def show_documentation(self):
        docs = """CyberShield NIDS Documentation

Network Intrusion Detection System that monitors for:
- DDoS attacks
- Port scanning
- DoS attacks
- UDP floods
- HTTP/HTTPS floods

Usage:
1. Enter target IP address
2. Click Start Monitoring
3. View detected threats in logs
4. Use terminal for network diagnostics

Detection Methods:
- SYN flood detection
- Port scan detection
- Rate-based flood detection
- Protocol analysis
"""
        messagebox.showinfo("Documentation", docs)
    
    def show_about(self):
        about = """Accurate Cyber Defense Network Packet Filter
Advanced Network Intrusion Detection System
with real-time threat detection and network
monitoring capabilities.

Developed by Ian Carter Kulani
© 2025 All Rights Reserved
"""
        messagebox.showinfo("About", about)

def main():
    root = tk.Tk()
    app = CyberShieldNIDS(root)
    root.mainloop()

if __name__ == "__main__":
    main()