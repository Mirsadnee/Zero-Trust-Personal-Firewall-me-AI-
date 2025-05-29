#!/usr/bin/env python3
import os
import sys
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import psutil
import logging
from datetime import datetime
import json
from pathlib import Path
from ml_analyzer import NetworkBehaviorAnalyzer

# Konfiguro logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall.log'),
        logging.StreamHandler()
    ]
)

class ZeroTrustFirewall:
    def __init__(self):
        self.known_apps = {}
        self.suspicious_ips = set()
        self.rules = {}
        self.ml_analyzer = NetworkBehaviorAnalyzer()
        self.connection_history = {}
        self.ml_analyzer.load_model()
        self.load_known_apps()
        self.setup_packet_filter()
        logging.info("Firewall-i u inicializua me sukses")

    def load_known_apps(self):
        """Ngarko aplikacionet e njohura dhe modelet e tyre të rrjetit"""
        try:
            if os.path.exists('known_apps.json'):
                with open('known_apps.json', 'r') as f:
                    self.known_apps = json.load(f)
                logging.info("Aplikacionet e njohura u ngarkuan me sukses")
        except Exception as e:
            logging.error(f"Gabim gjatë ngarkimit të aplikacioneve: {e}")

    def save_known_apps(self):
        """Ruaj aplikacionet e njohura dhe modelet e tyre të rrjetit"""
        try:
            with open('known_apps.json', 'w') as f:
                json.dump(self.known_apps, f, indent=4)
            logging.info("Aplikacionet e njohura u ruajtën me sukses")
        except Exception as e:
            logging.error(f"Gabim gjatë ruajtjes së aplikacioneve: {e}")

    def get_process_info(self, pid):
        """Merr informacionin e procesit për një PID të dhënë"""
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'path': process.exe(),
                'cmdline': process.cmdline()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_connection_key(self, src_ip, dst_ip, sport, dport, proto):
        """Gjenero një çelës unik për një lidhje"""
        return f"{src_ip}:{sport}-{dst_ip}:{dport}-{proto}"

    def update_connection_history(self, packet, process_info):
        """Përditëso historinë e lidhjeve me informacionin e paketës"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                proto = "TCP"
                window_size = packet[TCP].window
                tcp_flags = packet[TCP].flags
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                proto = "UDP"
                window_size = 0
                tcp_flags = 0
            else:
                return

            conn_key = self.get_connection_key(src_ip, dst_ip, sport, dport, proto)
            
            if conn_key not in self.connection_history:
                self.connection_history[conn_key] = {
                    'start_time': datetime.now(),
                    'packet_count': 0,
                    'total_bytes': 0,
                    'last_packet_time': datetime.now(),
                    'process_info': process_info
                }

            history = self.connection_history[conn_key]
            history['packet_count'] += 1
            history['total_bytes'] += len(packet)
            history['last_packet_time'] = datetime.now()

            # Llogarit delta kohore dhe shpejtësinë e paketave
            time_delta = (history['last_packet_time'] - history['start_time']).total_seconds()
            packet_rate = history['packet_count'] / time_delta if time_delta > 0 else 0

            # Përgatit të dhënat e paketës për analizën ML
            packet_data = {
                'packet_size': len(packet),
                'protocol': 1 if proto == "TCP" else 2,
                'src_port': sport,
                'dst_port': dport,
                'ttl': packet[IP].ttl,
                'window_size': window_size,
                'tcp_flags': tcp_flags,
                'time_delta': time_delta,
                'packet_rate': packet_rate,
                'connection_duration': time_delta
            }

            return packet_data

    def packet_callback(self, packet):
        """Procesoj çdo paketë të rrjetit"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            try:
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    proto = "TCP"
                elif UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    proto = "UDP"
                else:
                    return

                # Merr informacionin e procesit
                process_info = self.get_process_info(os.getpid())
                
                if process_info:
                    app_name = process_info['name']
                    if app_name not in self.known_apps:
                        logging.warning(f"U zbulua aplikacion i ri: {app_name}")
                        self.handle_new_application(app_name, process_info)
                    
                    # Përditëso historinë e lidhjeve dhe merr të dhënat e paketës
                    packet_data = self.update_connection_history(packet, process_info)
                    
                    if packet_data:
                        # Analizo sjelljen duke përdorur ML
                        suspicious_score = self.ml_analyzer.analyze_behavior(packet_data)
                        
                        # Nëse rezultati i dyshimit është i lartë, trajto si lidhje të dyshimtë
                        if suspicious_score > 0.8:
                            logging.warning(f"U zbulua lidhje e dyshimtë (rezultati: {suspicious_score:.2f})")
                            self.handle_suspicious_connection(packet, suspicious_score)
                            
                            # Përditëso modelin ML me këtë shembull
                            self.ml_analyzer.update_model(packet_data, True)

            except Exception as e:
                logging.error(f"Gabim gjatë procesimit të paketës: {e}")

    def handle_new_application(self, app_name, process_info):
        """Trajto aplikacionet e sapo zbuluara"""
        print(f"\nU zbulua aplikacion i ri: {app_name}")
        print(f"Rruga: {process_info['path']}")
        response = input("Lejo këtë aplikacion? (p/j): ").lower()
        
        if response == 'p':
            self.known_apps[app_name] = {
                'path': process_info['path'],
                'allowed': True,
                'first_seen': datetime.now().isoformat()
            }
            self.save_known_apps()
            logging.info(f"Aplikacioni {app_name} u lejua")
        else:
            self.known_apps[app_name] = {
                'path': process_info['path'],
                'allowed': False,
                'first_seen': datetime.now().isoformat()
            }
            self.save_known_apps()
            logging.info(f"Aplikacioni {app_name} u bllokua")

    def handle_suspicious_connection(self, packet, suspicious_score):
        """Trajto lidhjet e dyshimta"""
        print("\nU zbulua lidhje e dyshimtë!")
        print(f"Rezultati i dyshimit: {suspicious_score:.2f}")
        print(f"Burimi: {packet[IP].src}")
        print(f"Destinacioni: {packet[IP].dst}")
        response = input("Blloko këtë lidhje? (p/j): ").lower()
        
        if response == 'p':
            self.suspicious_ips.add(packet[IP].dst)
            logging.info(f"Lidhja me {packet[IP].dst} u bllokua")
        else:
            logging.info(f"Lidhja me {packet[IP].dst} u lejua")

    def setup_packet_filter(self):
        """Konfiguro filtrin e paketave"""
        try:
            # Konfiguro filtrin e paketave
            sniff(prn=self.packet_callback, store=0)
        except Exception as e:
            logging.error(f"Gabim gjatë konfigurimit të filtrit të paketave: {e}")
            sys.exit(1)

def main():
    print("Duke nisur Firewall-in Zero Trust...")
    print("Shtyp Ctrl+C për të ndaluar")
    
    firewall = ZeroTrustFirewall()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDuke ndaluar firewall-in...")
        sys.exit(0)

if __name__ == "__main__":
    main() 