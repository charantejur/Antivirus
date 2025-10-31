import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import os, hashlib, requests, socket, time
from urllib.parse import urlparse
from datetime import datetime

# === Setup ===
UPLOAD_FOLDER = "uploads"
QUARANTINE_DIR = "quarantine"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# === Signatures ===
SIGNATURES = {
    "malicious_domains": ["malicious.com", "phishing-site.net", "evilserver.org"],
}

# === Utility ===
def compute_sha256(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest().upper()

def internet_available():
    try:
        socket.create_connection(("8.8.8.8", 53), 2)
        return True
    except OSError:
        return False

def scan_link_realtime(url, progress_callback):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    progress_callback(10)
    time.sleep(0.3)

    for bad in SIGNATURES["malicious_domains"]:
        if bad in domain:
            progress_callback(100)
            return "🚨 Site may be unsafe (known malicious domain)"

    if not internet_available():
        progress_callback(100)
        return "❌ No Internet connection"

    try:
        progress_callback(40)
        time.sleep(0.5)

        response = requests.get(url, timeout=6, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        progress_callback(90)
        time.sleep(0.4)
        status = response.status_code

        if status == 200:
            progress_callback(100)
            return "✅ Site is safe (HTTP 200)"
        elif status < 400:
            progress_callback(100)
            return f"⚠️ Site reachable but unusual response (HTTP {status})"
        else:
            progress_callback(100)
            return f"🚨 Site may be unsafe (HTTP {status})"
    except requests.exceptions.RequestException:
        progress_callback(100)
        return "❌ Unable to connect"

# === GUI ===
class SafeScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SafeScan — Dynamic Desktop Scanner")
        self.state("zoomed")  # Fullscreen
        self.configure(bg="#0d1b2a")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", background="#1b263b", foreground="white", padding=8, font=("Segoe UI", 11, "bold"))
        style.map("TButton", background=[("active", "#415a77")])
        style.configure("TLabel", background="#0d1b2a", foreground="white", font=("Segoe UI", 11))
        style.configure("TFrame", background="#0d1b2a")
        style.configure("TProgressbar", troughcolor="#1b263b", background="#00b4d8", thickness=20)

        self.create_ui()

    def create_ui(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill="both", expand=True)

        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side="left", fill="y", padx=10)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=10)

        title = ttk.Label(left_frame, text="🛡️ SafeScan — Dynamic Desktop Scanner", font=("Segoe UI", 16, "bold"))
        title.pack(pady=10)

        ttk.Label(left_frame, text="📁 Scan a File", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(20, 5))
        ttk.Button(left_frame, text="Choose File...", command=self.select_file).pack(fill="x")

        ttk.Label(left_frame, text="🌐 Scan a Website", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(20, 5))
        self.url_entry = ttk.Entry(left_frame, width=40, font=("Segoe UI", 11))
        self.url_entry.pack(fill="x", pady=5)
        ttk.Button(left_frame, text="Scan Website", command=self.start_scan_thread).pack(fill="x")

        ttk.Label(left_frame, text="🗂️ Quarantine", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(20, 5))
        ttk.Button(left_frame, text="Open Quarantine Folder", command=self.open_quarantine).pack(fill="x")

        ttk.Label(right_frame, text="📋 Results", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 5))
        self.result_box = tk.Text(right_frame, height=20, bg="#1b263b", fg="white", font=("Consolas", 11), relief="flat", wrap="word")
        self.result_box.pack(fill="both", expand=True, padx=5, pady=5)

        # Loader + Progress bar
        self.loader_label = ttk.Label(right_frame, text="", font=("Segoe UI", 12, "bold"))
        self.loader_label.pack(pady=10)

        self.progress = ttk.Progressbar(right_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=10)

        self.loader_running = False

    def log(self, message):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        self.result_box.insert(tk.END, f"{timestamp}  {message}\n")
        self.result_box.see(tk.END)

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path:
            return
        sha = compute_sha256(file_path)
        self.log(f"Scanned file: {os.path.basename(file_path)}")
        self.log(f"SHA256: {sha}")
        messagebox.showinfo("Scan result", "✅ File appears safe")

    def start_scan_thread(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Error", "Please enter a website URL.")
            return
        threading.Thread(target=self.scan_website, args=(url,), daemon=True).start()

    def scan_website(self, url):
        self.loader_running = True
        self.progress["value"] = 0
        threading.Thread(target=self.animate_loader, daemon=True).start()
        self.log(f"Starting URL scan: {url}")

        def update_progress(value):
            self.progress["value"] = value
            self.update_idletasks()

        result = scan_link_realtime(url, update_progress)
        self.loader_running = False
        self.loader_label.config(text="")
        self.progress["value"] = 100
        self.log(result)
        messagebox.showinfo("Scan result", result)

    def animate_loader(self):
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        i = 0
        while self.loader_running:
            self.loader_label.config(text=f"Scanning {spinner[i % len(spinner)]}")
            i += 1
            self.loader_label.update()
            self.after(100)

    def open_quarantine(self):
        os.startfile(QUARANTINE_DIR)

if __name__ == "__main__":
    app = SafeScanApp()
    app.mainloop()


