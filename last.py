import uuid  


import sys
import threading
import time
from collections import defaultdict
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, IP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from tkinter import *
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import requests
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import Table, TableStyle
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet6 import IPv6  # Add this import at the top with other scapy imports
from reportlab.lib import colors  # Add this import at the top

VIRUSTOTAL_API_KEY = "b0f14a8c90ffbd4f168ceb42d64beff77578d648bcef9ebe36b3b799c25d66ba"

PROTOCOL_NAMES = {
    0: "HOPOPT",    1: "ICMP",     2: "IGMP",     3: "GGP",      4: "IP-in-IP",
    5: "ST",        6: "TCP",      7: "CBT",      8: "EGP",      9: "IGP",
    10: "BBN-RCC", 11: "NVP",     12: "PUP",     13: "ARGUS",   14: "EMCON",
    15: "XNET",    16: "CHAOS",   17: "UDP",     18: "MUX",     19: "DCN-MEAS",
    20: "HMP",     21: "PRM",     22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2",
    25: "LEAF-1",  26: "LEAF-2",  27: "RDP",     28: "IRTP",    29: "ISO-TP4",
    30: "NETBLT",  31: "MFE-NSP", 32: "MERIT",   33: "DCCP",    34: "3PC",
    35: "IDPR",    36: "XTP",     37: "DDP",     38: "IDPR-CMTP", 39: "TP++",
    40: "IL",      41: "IPv6",    42: "SDRP",    43: "IPv6-Route", 44: "IPv6-Frag",
    45: "IDRP",    46: "RSVP",    47: "GRE",     48: "DSR",     49: "BNA",
    50: "ESP",     51: "AH",      52: "I-NLSP",  53: "DNS",     54: "NARP",
    55: "MOBILE",  56: "TLSP",    57: "SKIP",    58: "IPv6-ICMP", 59: "IPv6-NoNxt",
    60: "IPv6-Opts", 61: "ANY",   62: "CFTP",    63: "ANY",     64: "SAT-EXPAK",
    65: "KRYPTOLAN", 66: "RVD",   67: "IPPC",    68: "ANY",     69: "SAT-MON",
    70: "VISA",    71: "IPCU",    72: "CPNX",    73: "CPHB",    74: "WSN",
    75: "PVP",     76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK",
    80: "HTTP",    81: "ISO-IP",  82: "VMTP",    83: "SECURE-VMTP", 84: "VINES",
    85: "TTP",     86: "NSFNET-IGP", 87: "DGP",  88: "TCF",     89: "OSPF",
    90: "Sprite-RPC", 91: "LARP", 92: "MTP",     93: "AX.25",   94: "IPIP",
    95: "MICP",    96: "SCC-SP",  97: "ETHERIP", 98: "ENCAP",   99: "ANY",
    443: "HTTPS"
}

class NetworkAnalyzer:
    def __init__(self):
        self.root = Tk()
        self.root.title("NetSpector Pro")
        self.root.geometry("1400x900")
        
        # Initialize variables
        self.capturing = False
        self.packet_counter = 1
        self.packets = []
        self.arp_table = defaultdict(list)
        self.ddos_counts = defaultdict(int)
        self.ddos_threshold = 100
        self.ssh_attempts = defaultdict(int)
        self.telnet_attempts = defaultdict(int)
        self.selected_interface = conf.iface  # Default interface
        self.SERVICE_PORTS = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            23: "Telnet",
            53: "DNS",
            21: "FTP",
            25: "SMTP",
            3389: "RDP",}
        
        # Create GUI
        self.create_widgets()
        self.setup_layout()

    # ------------------- GUI Components -------------------
    def create_widgets(self):
        # Create toolbar first
        self.toolbar = Frame(self.root)
        
        # Then create search frame
        self.search_frame = Frame(self.toolbar)
        self.search_var = StringVar()
        self.search_entry = Entry(self.search_frame, textvariable=self.search_var, width=30)
        self.search_btn = Button(self.search_frame, text="Search", command=self.filter_packets)
        self.clear_btn = Button(self.search_frame, text="Clear", command=self.clear_search)
        
        # Create other toolbar buttons
        self.start_btn = Button(self.toolbar, text="Start Capture", command=self.start_capture)
        self.stop_btn = Button(self.toolbar, text="Stop", command=self.stop_capture, state=DISABLED)
        self.import_btn = Button(self.toolbar, text="Import PCAP", command=self.import_pcap)
        self.save_pcap_btn = Button(self.toolbar, text="Save PCAP", command=self.save_pcap)
        self.save_report_btn = Button(self.toolbar, text="Generate Report", command=self.generate_full_report)
        
        # Create packet table and alerts section
        self.columns = ('ID', 'Time', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info')
        self.tree = ttk.Treeview(self.root, columns=self.columns, show='headings')
        for col in self.columns:
            self.tree.heading(col, text=col, command=lambda _col=col: self.sort_column(_col))
            self.tree.column(col, anchor=CENTER, stretch=YES)
        
        self.alert_text = Text(self.root, height=15, bg='black', fg='white')
        self.alert_text.tag_config('warning', foreground='yellow')
        self.alert_text.tag_config('danger', foreground='red')

    def setup_layout(self):
        self.toolbar.pack(side=TOP, fill=X, padx=5, pady=5)
        self.start_btn.pack(side=LEFT, padx=2)
        self.stop_btn.pack(side=LEFT, padx=2)
        self.import_btn.pack(side=LEFT, padx=2)
        self.search_frame.pack(side=RIGHT, padx=10)
        self.search_entry.pack(side=LEFT, padx=2)
        self.search_btn.pack(side=LEFT, padx=2)
        self.clear_btn.pack(side=LEFT, padx=2)

        self.save_pcap_btn.pack(side=LEFT, padx=2)
        self.save_report_btn.pack(side=LEFT, padx=2)
        
        self.tree.pack(fill=BOTH, expand=True, padx=5, pady=5)
        self.alert_text.pack(fill=BOTH, expand=False, padx=5, pady=5)

    def filter_packets(self):
        search_term = self.search_var.get().lower()
        if not search_term:  # If search is empty, show all packets
            self.update_table()
            return
            
        filtered = []
        for pkt in self.packets:
            try:
                # Check IP addresses
                ip_match = (search_term in str(pkt[2]).lower() or 
                          search_term in str(pkt[3]).lower())
                
                # Check protocol
                protocol_match = search_term in str(pkt[4]).lower()
                
                # Check info field
                info_match = search_term in str(pkt[6]).lower()
                
                # Check port numbers
                port_match = False
                if "→" in str(pkt[6]):
                    ports = str(pkt[6]).split("→")
                    if len(ports) > 1:
                        port_match = search_term in ports[0] or search_term in ports[1].split()[0]
                
                if ip_match or protocol_match or info_match or port_match:
                    filtered.append(pkt)
                    
            except Exception as e:
                print(f"Search error for packet: {e}")
                continue
        
        # Update table with filtered results
        self.tree.delete(*self.tree.get_children())
        for pkt in filtered:
            self.tree.insert("", "end", values=pkt)

    def clear_search(self):
        self.search_var.set("")
        self.update_table(self.packets)

    def update_table(self, packets=None):
        """Update the packet display table with either specified packets or all stored packets"""
        self.tree.delete(*self.tree.get_children())
        target = packets if packets else self.packets[-1000:]  # Show last 1000 packets for performance
        for pkt in target:
            self.tree.insert("", "end", values=pkt)

    def sort_column(self, col):
        """Sort table by column"""
        try:
            # Get all items from the tree
            items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
            
            # Convert values for proper sorting
            if col in ['ID', 'Length']:
                # Sort numerically
                items = [(int(value), item) for value, item in items]
            
            # Sort items
            items.sort(reverse=self.tree.heading(col).get('reverse', False))
            
            # Rearrange items in sorted positions
            for idx, (val, item) in enumerate(items):
                self.tree.move(item, '', idx)
            
            # Reverse sort next time
            self.tree.heading(col, 
                            text=col,
                            command=lambda _col=col: self.sort_column(_col))
            self.tree.heading(col, reverse=not self.tree.heading(col).get('reverse', False))
            
        except Exception as e:
            print(f"Sort error: {e}")

    # ------------------- Packet Processing -------------------
    def start_capture(self):
        self.capturing = True
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.alert_text.delete(1.0, END)
        
        capture_thread = threading.Thread(target=self.sniff_packets)
        capture_thread.daemon = True
        capture_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)

    def sniff_packets(self):
        sniff(
            iface=self.selected_interface,
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: not self.capturing
        )

    def process_packet(self, packet):
        try:
            packet_id = str(uuid.uuid4())[:8]
            packet_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
            
            # Layer parsing
            src_ip = packet[IP].src if IP in packet else (
                packet[IPv6].src if IPv6 in packet else "N/A"
            )
            dst_ip = packet[IP].dst if IP in packet else (
                packet[IPv6].dst if IPv6 in packet else "N/A"
            )
            protocol = PROTOCOL_NAMES.get(packet[IP].proto, str(packet[IP].proto)) if IP in packet else "L2"
            
            # Build detailed info
            info = []
            if Ether in packet:
                info.append(f"MAC: {packet[Ether].src} -> {packet[Ether].dst}")
            if TCP in packet:
                info.append(f"TCP [{packet[TCP].sport}→{packet[TCP].dport} Flags:{packet[TCP].flags}]")
            if HTTPRequest in packet:
                info.append(f"HTTP {packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Host.decode()}")
            if DNS in packet and packet[DNS].qr == 0:
                info.append(f"DNS Query: {packet[DNSQR].qname.decode()}")
            # Add more protocol handlers as needed
            
            info_str = " | ".join(info) if info else packet.summary()
            
            # Store packet
            self.packets.append((packet_id, packet_time, src_ip, dst_ip, protocol, len(packet), info_str))
            self.root.after(0, self.update_table)
            
            # Threat detection (existing code)
            self.detect_arp_spoofing(packet)
            self.detect_ddos(packet)
            self.detect_ssh_bruteforce(packet)
            self.detect_telnet_bruteforce(packet)
            self.detect_syn_flood(packet)
            
            # VirusTotal Integration
            if HTTPRequest in packet:
                http_layer = packet[HTTPRequest]
                url = f"http://{http_layer.Host.decode()}{http_layer.Path.decode()}"
                malicious = self.check_url_virustotal(url)
                if malicious > 0:
                    self.alert(f"[VirusTotal] Malicious URL: {url} ({malicious} engines)", 'danger')
            
        except Exception as e:
            print(f"Packet processing error: {e}")
        # ------------------- Threat Detection -------------------
    def detect_arp_spoofing(self, packet):
        if ARP in packet and packet[ARP].op == 2:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            if ip in self.arp_table and mac not in self.arp_table[ip]:
                self.alert(f"[ARP Spoofing] IP: {ip} MAC: {mac}", 'danger')
            self.arp_table[ip].append(mac)

    def detect_ddos(self, packet):
        if IP in packet:
            dst_ip = packet[IP].dst
            self.ddos_counts[dst_ip] += 1
            if self.ddos_counts[dst_ip] > self.ddos_threshold:
                self.alert(f"[DDoS] Target: {dst_ip} Packets: {self.ddos_counts[dst_ip]}", 'warning')

    def detect_syn_flood(self, packet):
        if TCP in packet and packet[TCP].flags == 'S':
            src_ip = packet[IP].src
            self.ddos_counts[src_ip] += 1
            if self.ddos_counts[src_ip] > self.ddos_threshold:
                self.alert(f"[SYN Flood] From: {src_ip}", 'danger')

    def detect_ssh_bruteforce(self, packet):
        if TCP in packet and packet[TCP].dport == 22:
            src_ip = packet[IP].src
            self.ssh_attempts[src_ip] += 1
            if self.ssh_attempts[src_ip] > 5:
                self.alert(f"[SSH Bruteforce] From: {src_ip}", 'danger')

    def detect_telnet_bruteforce(self, packet):
        if TCP in packet and packet[TCP].dport == 23:
            src_ip = packet[IP].src
            self.telnet_attempts[src_ip] += 1
            if self.telnet_attempts[src_ip] > 5:
                self.alert(f"[Telnet Bruteforce] From: {src_ip}", 'danger')

    # ------------------- VirusTotal Integration -------------------
    def check_url_virustotal(self, url):
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            if response.status_code == 200:
                result = response.json()
                return result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        except Exception as e:
            print(f"VirusTotal Error: {e}")
        return 0

    # ------------------- File Management -------------------
    def import_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap *.pcapng")])
        if file_path:
            try:
                # Clear existing data
                self.packets.clear()
                self.tree.delete(*self.tree.get_children())
                
                # Load new packets
                packets = rdpcap(file_path)
                for packet in packets:
                    self.process_packet(packet)
                    
                    # Run security checks
                    self.detect_arp_spoofing(packet)
                    self.detect_ddos(packet)
                    self.detect_ssh_bruteforce(packet)
                    self.detect_telnet_bruteforce(packet)
                    self.detect_syn_flood(packet)
                
                # Generate statistics
                proto_stats = self.get_protocol_statistics()
                self.alert("\n[Statistics] Protocol Distribution:", 'info')
                for proto, count in proto_stats.items():
                    self.alert(f"  {proto}: {count} packets", 'info')
                
                messagebox.showinfo("Success", 
                    f"Analysis Complete!\n"
                    f"- Total Packets: {total}\n"
                    f"- Unique Protocols: {len(proto_stats)}\n"
                    f"- Time Range: {self.packets[0][1]} to {self.packets[-1][1]}")
                
            except Exception as e:
                messagebox.showerror("Error", f"PCAP import failed: {e}")

    def save_pcap(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")]
        )
        if file_path:
            try:
                # تحويل الحزم المخزنة إلى قائمة Scapy
                scapy_packets = [pkt[6] for pkt in self.packets if isinstance(pkt[6], Packet)]
                wrpcap(file_path, scapy_packets)
                messagebox.showinfo("Success", "PCAP file saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save PCAP: {e}")          

    # ------------------- Reporting -------------------
    def generate_full_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf")
        if file_path:
            self.create_pdf_report(file_path)

    def create_pdf_report(self, filename):
        try:
            # PDF Setup
            c = canvas.Canvas(filename, pagesize=letter)
            width, height = letter
            margin = 50
            line_height = 15
            page_number = 1

            # Styling Configuration - Remove color strings, use RGB tuples instead
            styles = {
                'header': ('Helvetica-Bold', 14),
                'subheader': ('Helvetica-Bold', 12),
                'body': ('Helvetica', 10),
                'table_header': ('Helvetica-Bold', 10),
                'warning': ('Helvetica-Bold', 10),
                'critical': ('Helvetica-Bold', 10)
            }

            def draw_header(title):
                nonlocal height
                c.setFont(styles['header'][0], styles['header'][1])
                c.drawString(margin, height - margin, title)
                c.setFont(styles['body'][0], 8)
                c.drawRightString(width - margin, height - margin, 
                                f"Page {page_number} - Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                height -= 40

            # ========== Summary Page ==========
            draw_header("Network Analysis Report - Summary")

            # Protocol Distribution
            protocol_stats = self.get_protocol_statistics()
            total_packets = sum(protocol_stats.values())
            protocol_data = [["Protocol", "Count", "Percentage"]]
            for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
                percentage = f"{(count/total_packets)*100:.2f}%" if total_packets else "0.00%"
                protocol_data.append([proto, str(count), percentage])

            # Create protocol table
            proto_table = Table(protocol_data, colWidths=[150, 80, 100])
            proto_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 10),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.gray),
                ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F8F8F8'))
            ]))
            proto_table.wrapOn(c, width - 2*margin, height)
            proto_table.drawOn(c, margin, height - 120)

            # ========== Detailed Packet Listing ==========
            c.showPage()
            page_number += 1
            draw_header("Network Analysis Report - Packet Details")
            
            # Packet Table - Increase Info column width
            packet_data = [["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]]
            for idx, pkt in enumerate(self.packets, 1):
                packet_data.append([
                    str(idx),
                    str(pkt[1].split()[1]) if pkt[1] else "N/A",
                    str(pkt[2]),
                    str(pkt[3]),
                    str(pkt[4]),
                    str(pkt[5]),
                    str(pkt[6][:150]) if pkt[6] else ""  # Increased from 75 to 150 characters
                ])

            # Wider column widths
            packet_table = Table(packet_data, colWidths=[40, 70, 100, 100, 70, 50, 300])  # Increased Info width
            packet_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 8),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#DDDDDD')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8F8F8')]),
                ('WORDWRAP', (6,0), (6,-1), True)  # Enable word wrapping for Info column
            ]))
            packet_table.wrapOn(c, width - 2*margin, height)
            packet_table.drawOn(c, margin, height - 700)

            # ========== Threat Details Page ==========
            c.showPage()
            page_number += 1
            draw_header("Network Analysis Report - Threat Details")

            # Threat Table (Fixed data validation)
            threat_data = [["Time", "Threat Type", "Source", "Details"]]
            for threat in self.get_threats():
                threat_data.append([
                    str(threat[0]), 
                    str(threat[1]), 
                    str(threat[2]), 
                    str(threat[3])[:200]  # Limit detail length
                ])

            threat_table = Table(threat_data, colWidths=[80, 100, 150, 200])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#990000')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 9),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#FFAAAA')),
                ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#FFF0F0'))
            ]))
            threat_table.wrapOn(c, width - 2*margin, height)
            threat_table.drawOn(c, margin, height - 700)

            c.save()
            messagebox.showinfo("Success", f"Report generated successfully!\nSaved to: {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PDF report: {str(e)}")

    def get_protocol_statistics(self):
        stats = defaultdict(int)
        for pkt in self.packets:
            stats[pkt[4]] += 1
        return dict(stats)

    def get_threats(self):
        threats = []
        alerts = self.alert_text.get("1.0", END).split("\n")
        for alert in alerts:
            if alert.strip():
                # استخراج الوقت من البداية [HH:MM:SS]
                time = alert[1:9] if len(alert) > 9 else "N/A"
                
                # استخراج نوع التهديد والمعلومات
                if "[DDoS]" in alert:
                    threat_type = "DDoS"
                    source = alert.split("Target: ")[1].split(" ")[0]
                    details = alert.split("] ")[1]
                elif "[SYN Flood]" in alert:
                    threat_type = "SYN Flood"
                    source = alert.split("From: ")[1].strip()
                    details = alert.split("] ")[1]
                elif "[SSH Bruteforce]" in alert:
                    threat_type = "SSH Bruteforce"
                    source = alert.split("From: ")[1].strip()
                    details = alert.split("] ")[1]
                elif "[Telnet Bruteforce]" in alert:
                    threat_type = "Telnet Bruteforce"
                    source = alert.split("From: ")[1].strip()
                    details = alert.split("] ")[1]
                elif "[ARP Spoofing]" in alert:
                    threat_type = "ARP Spoofing"
                    parts = alert.split("IP: ")[1].split(" MAC: ")
                    source = f"IP: {parts[0]}, MAC: {parts[1]}"
                    details = alert.split("] ")[1]
                else:
                    continue
                
                threats.append([time, threat_type, source, details])
        return threats

    # ------------------- Utilities -------------------
    def alert(self, message, level='warning', timestamp=None):
        """Add an alert message to the alert text box"""
        if not timestamp:
            timestamp = f"[{time.strftime('%H:%M:%S')}]"
        
        self.alert_text.insert(END, f"{timestamp} {message}\n", level)
        self.alert_text.see(END)
        self.alert_text.update()

if __name__ == "__main__":
    app = NetworkAnalyzer()
    app.root.mainloop()