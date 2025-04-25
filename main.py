
import os
import sys
import tkinter as tk
from tkinter import messagebox
import threading
from tkinter import ttk
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, DNSQR
import socket
import requests
import json
import csv
from functools import lru_cache
from datetime import datetime
import schedule
import time
from queue import Queue


ABUSE_API_KEY = "23825c7729c2378d908cdfe4894a0b0f3e98b057d8f3a5e33b50fae564de87c2dbad9df83575dd00" 
BLACKLIST_CACHE_FILE = "blacklist_cache.csv"
blacklist_cache = {}

if os.path.exists(BLACKLIST_CACHE_FILE):
    with open(BLACKLIST_CACHE_FILE, mode="r") as file:
        reader = csv.reader(file)
        blacklist_cache = {rows[0]: rows[1] for rows in reader}

packet_queue = Queue()

def is_admin():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

local_ip = get_local_ip()

suspicious_keywords = [b'malware', b'cmd.exe', b'powershell', b'exe', b'exploit', b'/bin/sh', b'../', b'payload']

def is_suspicious(payload):
    lower_payload = payload.lower()
    return any(keyword in lower_payload for keyword in suspicious_keywords)

def get_website_name(packet):
    if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
        return packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip('.')
    return None

def get_ip_info(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

packet_data = pd.DataFrame(columns=["Timestamp", "Direction", "Protocol", "Source", "Destination", "Payload", "Size", "Details"])


def packet_callback(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            direction = "Outgoing" if src == local_ip else "Incoming"

            proto = "OTHER"
            sport = dport = "-"
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            website_name = get_website_name(packet)
            payload_size_bits = len(packet) * 8

            payload = packet[Raw].load if Raw in packet else b""
            try:
                payload_str = payload.decode(errors='ignore')
            except AttributeError:
                payload_str = ""

            blacklisted_src = is_blacklisted(src)
            blacklisted_dst = is_blacklisted(dst)

            if direction == "Incoming" and blacklisted_src:
                block_ip_windows(src)
            elif direction == "Outgoing" and blacklisted_dst:
                block_ip_windows(dst)

            suspicious = is_suspicious(payload)
            suspicious_flag = suspicious or blacklisted_src or blacklisted_dst

            suspicious_note = ""
            if suspicious:
                suspicious_note += "⚠️ Suspicious Payload "
            if blacklisted_src or blacklisted_dst:
                suspicious_note += "⚠️ Blacklisted IP "

            new_row = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Direction": direction,
                "Protocol": proto,
                "Source": f"{src}:{sport}",
                "Destination": f"{dst}:{dport}",
                "Payload": payload_str,
                "Size": f"{payload_size_bits} bits",
                "Details": suspicious_note or (website_name if website_name else "")
            }

            packet_queue.put(new_row)
    except Exception as e:
        print(f"Packet processing error: {e}")


def update_table(window):
    try:
        while not packet_queue.empty():
            new_row = packet_queue.get_nowait()
            
            global packet_data
            packet_data = pd.concat([packet_data, pd.DataFrame([new_row])], ignore_index=True)
            
            table.insert("", "end", values=(
                new_row["Timestamp"],
                new_row["Direction"],
                new_row["Protocol"],
                new_row["Source"],
                new_row["Destination"],
                new_row["Payload"][:100],  
                new_row["Size"],
                new_row["Details"]
            ))
            table.yview_moveto(1)
    finally:
        window.after(10, lambda: update_table(window))

def show_packet_details(event):
    selected_item = table.selection()
    if selected_item:
        item = table.item(selected_item)
        details = "\n".join([f"{col}: {val}" for col, val in zip(table["columns"], item["values"])])
        messagebox.showinfo("Packet Details", details)

def generate_daily_report():
    try:
        daily_report = packet_data[packet_data["Details"].str.contains("⚠️")].groupby("Details").size()
        timestamp = datetime.now().strftime("%Y-%m-%d")
        daily_report.to_csv(f"malicious_report_{timestamp}.csv")
    except Exception as e:
        print(f"Report error: {e}")

def schedule_reports():
    schedule.every().day.at("00:00").do(generate_daily_report)
    while True:
        schedule.run_pending()
        time.sleep(60)

def start_sniffing():
    # sniff(prn=packet_callback, store=False, filter="ip", timeout=30)
    while True:
        try:
            sniff(prn=packet_callback, store=False, filter="ip")
        except Exception as e:
            print(f"Sniffing error: {e}")
            time.sleep(1)

def save_ip_to_cache(ip, status):
    blacklist_cache[ip] = status
    with open(BLACKLIST_CACHE_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([ip, status])
        
def block_ip_windows(ip):
    try:
        print(f"Blocking IP: {ip}")
        os.system(f'netsh advfirewall firewall add rule name="Blocked IP {ip}" dir=in action=block remoteip={ip}')
        os.system(f'netsh advfirewall firewall add rule name="Blocked Outgoing {ip}" dir=out action=block remoteip={ip}')
    except Exception as e:
        print(f"Failed to block IP {ip}: {e}")


def is_blacklisted(ip):
    if ip in blacklist_cache:
        return blacklist_cache[ip] == "True"
    
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': ABUSE_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 50
        }

        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()
        abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)

        blacklisted = abuse_score >= 40
        save_ip_to_cache(ip, str(blacklisted))
        return blacklisted

    except Exception as e:
        print(f"Blacklist API error for {ip}: {e}")
        return False



def setup_ui():
    window = tk.Tk()
    window.title("Network Packet Analyzer")
    window.geometry("1200x600")

    window.grid_columnconfigure(0, weight=1)
    window.grid_rowconfigure(0, weight=1)

    global table
    table = ttk.Treeview(window, columns=("Timestamp", "Direction", "Protocol", "Source", "Destination", "Payload", "Size", "Details"), show="headings")
    scroll_y = ttk.Scrollbar(window, orient="vertical", command=table.yview)
    scroll_x = ttk.Scrollbar(window, orient="horizontal", command=table.xview)
    table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

    table.grid(row=0, column=0, sticky="nsew")
    scroll_y.grid(row=0, column=1, sticky="ns")
    scroll_x.grid(row=1, column=0, sticky="ew")

    col_widths = {
        "Timestamp": 150, "Direction": 80, "Protocol": 80,
        "Source": 200, "Destination": 200, "Payload": 300,
        "Size": 100, "Details": 50
    }
    for col, width in col_widths.items():
        table.heading(col, text=col)
        table.column(col, width=width, anchor="w")

    table.bind("<Double-1>", show_packet_details)
    
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    report_thread = threading.Thread(target=schedule_reports, daemon=True)
    sniff_thread.start()
    report_thread.start()

    update_table(window)
    window.mainloop()

if __name__ == "__main__":
    if not is_admin():
        print("Warning: Running without admin privileges may limit packet capture capabilities.")
    setup_ui()
