import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from main import ZeroTrustFirewall
import logging
import queue
import sys
from datetime import datetime

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Zero Trust me AI")
        self.root.geometry("800x600")
        
        # Konfiguro stilin
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#2196F3")
        self.style.configure("TLabel", padding=6, font=('Helvetica', 10))
        
        # Krijo frame-in kryesor
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Titulli
        self.title_label = ttk.Label(
            self.main_frame, 
            text="Firewall Zero Trust me AI", 
            font=('Helvetica', 16, 'bold')
        )
        self.title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Statusi
        self.status_frame = ttk.LabelFrame(self.main_frame, text="Statusi", padding="5")
        self.status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="Statusi: Duke u nisur...")
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Butonat e kontrollit
        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.start_button = ttk.Button(
            self.control_frame, 
            text="Nis Firewall-in",
            command=self.start_firewall
        )
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(
            self.control_frame, 
            text="Ndalo Firewall-in",
            command=self.stop_firewall,
            state='disabled'
        )
        self.stop_button.grid(row=0, column=1, padx=5)
        
        # Logu i aktiviteteve
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Logu i Aktivitetit", padding="5")
        self.log_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame, 
            wrap=tk.WORD, 
            width=70, 
            height=20
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Statistika
        self.stats_frame = ttk.LabelFrame(self.main_frame, text="Statistika", padding="5")
        self.stats_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.stats_label = ttk.Label(
            self.stats_frame, 
            text="Paketat e Analizuara: 0 | Lidhjet e Dyshimta: 0"
        )
        self.stats_label.grid(row=0, column=0, sticky=tk.W)
        
        # Konfiguro grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(3, weight=1)
        
        # Variablat e kontrollit
        self.firewall = None
        self.firewall_thread = None
        self.running = False
        self.log_queue = queue.Queue()
        
        # Konfiguro logging
        self.setup_logging()
        
        # Filloj të kontrolloj logun
        self.check_log_queue()

    def setup_logging(self):
        """Konfiguro logging për të shfaqur në GUI"""
        class QueueHandler(logging.Handler):
            def __init__(self, log_queue):
                super().__init__()
                self.log_queue = log_queue

            def emit(self, record):
                self.log_queue.put(record)

        # Shto handler-in e ri
        queue_handler = QueueHandler(self.log_queue)
        queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(queue_handler)

    def check_log_queue(self):
        """Kontrollo logun për mesazhe të reja"""
        while True:
            try:
                record = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, self.format_log_record(record) + '\n')
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        self.root.after(100, self.check_log_queue)

    def format_log_record(self, record):
        """Format mesazhin e logut"""
        return f"{datetime.fromtimestamp(record.created).strftime('%H:%M:%S')} - {record.levelname} - {record.getMessage()}"

    def start_firewall(self):
        """Nis firewall-in në një thread të veçantë"""
        if not self.running:
            self.running = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.status_label.config(text="Statusi: Duke punuar...")
            
            self.firewall = ZeroTrustFirewall()
            self.firewall_thread = threading.Thread(target=self.run_firewall)
            self.firewall_thread.daemon = True
            self.firewall_thread.start()

    def stop_firewall(self):
        """Ndalo firewall-in"""
        if self.running:
            self.running = False
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.status_label.config(text="Statusi: I ndaluar")
            
            if self.firewall:
                # TODO: Implemento metodën e ndalimit të firewall-it
                pass

    def run_firewall(self):
        """Ekzekuto firewall-in"""
        try:
            while self.running:
                # TODO: Implemento logjikën e firewall-it
                pass
        except Exception as e:
            logging.error(f"Gabim në firewall: {e}")
            self.running = False
            self.root.after(0, self.stop_firewall)

def main():
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 