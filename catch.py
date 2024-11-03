import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import sniff, IP, TCP
import time
import threading
import queue

# 프로토콜 번호 정의
protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")

        # 스타일 설정
        self.root.configure(bg="#e0f2f1")
        self.root.option_add("*Font", "Helvetica 12")
        self.root.option_add("*Label.Font", "Helvetica 18 bold")
        self.root.option_add("*Button.Background", "white")
        self.root.option_add("*Button.Foreground", "black")
        self.root.option_add("*Button.Font", "Helvetica 14 bold")
        self.root.option_add("*Treeview.Background", "white")
        self.root.option_add("*Treeview.Foreground", "black")
        self.root.option_add("*Treeview.Font", "Helvetica 12")
        self.root.option_add("*Treeview.Heading.Font", "Helvetica 14 bold")

        # GUI 요소 생성
        self.create_widgets()

        # 패킷 관련 변수 초기화
        self.packet_count = 0
        self.protocol_count = {'ICMP': 0, 'TCP': 0, 'UDP': 0}

        # 패킷 큐 및 스레드 초기화
        self.packet_queue = queue.Queue()
        self.sniffing_thread = None
        self.stop_sniffing = threading.Event()

        # Matplotlib 그래프 초기화
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        self.canvas.get_tk_widget().pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

    def create_widgets(self):
        # 제목 레이블
        self.label_title = tk.Label(self.root, text="Packet Sniffer", bg="#e0f2f1")
        self.label_title.pack(pady=20)

        # 패킷 로그 표
        self.tree_packets = ttk.Treeview(self.root, columns=("No.", "Time", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Length"), selectmode="browse")
        self.tree_packets.heading("#0", text="내용")
        self.tree_packets.heading("#1", text="No.")
        self.tree_packets.heading("#2", text="Time")
        self.tree_packets.heading("#3", text="Source IP")
        self.tree_packets.heading("#4", text="Destination IP")
        self.tree_packets.heading("#5", text="Source Port")
        self.tree_packets.heading("#6", text="Destination Port")
        self.tree_packets.heading("#7", text="Protocol")
        self.tree_packets.heading("#8", text="Length")
        self.tree_packets.column("#0", width=50, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#1", width=50, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#2", width=150, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#3", width=150, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#4", width=150, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#5", width=100, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#6", width=100, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#7", width=100, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.column("#8", width=100, stretch=tk.NO, anchor=tk.W)
        self.tree_packets.pack(pady=(0, 10), padx=20, fill=tk.BOTH, expand=True)

        # 통계 제목 레이블
        self.label_statistics = tk.Label(self.root, text="Statistics", bg="#e0f2f1")
        self.label_statistics.pack(pady=10)

        # 통계 내용 표
        self.tree_statistics = ttk.Treeview(self.root, columns=("Protocol", "Count"), show="headings", height=3)
        self.tree_statistics.heading("Protocol", text="Protocol")
        self.tree_statistics.heading("Count", text="Count")
        self.tree_statistics.column("Protocol", width=100, stretch=tk.NO, anchor=tk.W)
        self.tree_statistics.column("Count", width=100, stretch=tk.NO, anchor=tk.W)
        self.tree_statistics.pack(pady=10, padx=20, fill=tk.BOTH)

        # 시작 버튼
        self.button_start = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)
        self.button_start.pack(pady=10, padx=20)

        # 중지 버튼
        self.button_stop = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing_func)
        self.button_stop.pack(pady=10)

    def start_sniffing(self):
        self.packet_count = 0
        self.protocol_count = {'ICMP': 0, 'TCP': 0, 'UDP': 0}
        self.tree_packets.delete(*self.tree_packets.get_children())
        self.tree_statistics.delete(*self.tree_statistics.get_children())
        self.stop_sniffing.clear()

        # 스레드 시작
        self.sniffing_thread = threading.Thread(target=self.sniff_packets)
        self.sniffing_thread.start()

        # GUI 업데이트 스케줄링
        self.update_packets_in_gui()

        # 통계 그래프 업데이트 스케줄링
        self.root.after(1000, self.update_graph)

    def sniff_packets(self):
        def packet_callback(packet):
            self.packet_queue.put(packet)

        sniff(prn=packet_callback, stop_filter=lambda x: self.stop_sniffing.is_set())

    def update_packets_in_gui(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.packet_count += 1

            if IP in packet:
                ip_layer = packet[IP]
                ip_protocol = ip_layer.proto

                if ip_protocol in protocol_map:
                    protocol_name = protocol_map[ip_protocol]
                    self.protocol_count[protocol_name] += 1

                    time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                    length = len(packet)
                    source_port = ""
                    destination_port = ""

                    # TCP 패킷인 경우에만 소스 포트와 목적지 포트를 추출
                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        source_port = tcp_layer.sport
                        destination_port = tcp_layer.dport

                    self.tree_packets.insert("", "end", values=(self.packet_count, time_str, ip_layer.src, ip_layer.dst, source_port, destination_port, protocol_name, length))

                    self.update_statistics()

        # 스레드가 종료되지 않았으면 일정 시간 후 다시 호출
        if not self.stop_sniffing.is_set():
            self.root.after(1000, self.update_packets_in_gui)

    def update_statistics(self):
        self.tree_statistics.delete(*self.tree_statistics.get_children())
        for protocol, count in self.protocol_count.items():
            self.tree_statistics.insert("", "end", values=(protocol, count))

    def update_graph(self):
        labels = list(self.protocol_count.keys())
        counts = list(self.protocol_count.values())

        self.ax.clear()
        self.ax.bar(labels, counts, color=['blue', 'green', 'orange'])
        self.ax.set_xlabel('Protocol')
        self.ax.set_ylabel('Count')
        self.ax.set_title('Protocol Distribution')
        self.canvas.draw()

        # 일정 시간마다 그래프 업데이트
        self.root.after(1000, self.update_graph)

    def stop_sniffing_func(self):
        self.stop_sniffing.set()
        # 스레드가 종료될 때까지 기다림
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.sniffing_thread.join()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

    # 사용자가 Enter를 누를 때까지 대기
    input("Press Enter to exit...")