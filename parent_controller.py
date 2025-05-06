#!/usr/bin/env python3
import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import base64
from PIL import Image, ImageTk, ImageOps
from io import BytesIO
import datetime
import os
import time
import threading

# Configuration
CHILD_IP = "10.1.11.167"  # Change this to the child device's IP
PORT = 5500
DELIMITER = '|'
SOCKET_TIMEOUT = 15

# Command mappings
COMMAND_ARGS = {
    "BLOCK_SITE": ["Website"],
    "UNBLOCK_SITE": ["Website"],
    "GET_BLOCKED_SITES": [],
    "GET_RUNNING_APPS": [],
    "LOCK_SCREEN": [],
    "CHAT": ["Message"],
    "TIME_FILTER": ["Website", "Duration"],
    "GET_SCREENSHOT": [],
    "GET_ANOMALIES": []
}


def send_command(command):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((CHILD_IP, PORT))
            s.sendall(command.encode('utf-8'))
            
            if command.startswith("LOCK_SCREEN"):
                try:
                    response = s.recv(4096).decode('utf-8', errors='replace')
                    return response
                except socket.timeout:
                    return "SCREEN_LOCKED (No response received - this is normal for lock screen command)"
            
            response = b""
            while True:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    if response:
                        break
                    raise
            
            return response.decode('utf-8', errors='replace')
    except socket.timeout:
        return f"Error: Connection timed out. Verify the child device is running and accessible at {CHILD_IP}:{PORT}"
    except ConnectionRefusedError:
        return f"Error: Connection refused. Verify the child service is running at {CHILD_IP}:{PORT}"
    except Exception as e:
        return f"Error: {e}"


class NetGuardianGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetGuardian Parent Controller")
        self.geometry("1400x900")
        self.minsize(1000, 700)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.create_widgets()
        os.makedirs("screenshots", exist_ok=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.statusbar = ttk.Label(self, textvariable=self.status_var, 
                                 style='Status.TLabel', padding=(10, 5))
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.anomaly_polling_active = True
        self.anomaly_thread = threading.Thread(target=self.poll_for_anomalies, daemon=True)
        self.anomaly_thread.start()
        
        self.blocked_sites = []
        self.current_screenshot = None
        self.after(1000, self.refresh_blocked_sites)

    def configure_styles(self):
        self.style.configure('.', background='#f0f0f0', foreground='#2c3e50')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', font=('Helvetica', 10, 'bold'), padding=(15, 5))
        self.style.configure('Header.TLabel', font=('Helvetica', 11, 'bold'), foreground='#2c3e50')
        self.style.configure('Status.TLabel', background='#34495e', foreground='white')
        self.style.configure('TButton', font=('Helvetica', 9, 'bold'), borderwidth=1)
        self.style.map('TButton',
                      foreground=[('active', 'white'), ('!disabled', '#2c3e50')],
                      background=[('active', '#3498db'), ('!disabled', '#ecf0f1')])
        self.style.configure('Red.TButton', foreground='white', background='#e74c3c')
        self.style.configure('Green.TButton', foreground='white', background='#2ecc71')
        self.style.configure('TEntry', fieldbackground='white')
        self.style.configure('TCombobox', fieldbackground='white')

    def create_widgets(self):
        # Main paned window for split view
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Left pane (controls)
        left_pane = ttk.Frame(main_pane)
        main_pane.add(left_pane, weight=2)

        # Right pane (screenshot)
        right_pane = ttk.Frame(main_pane)
        main_pane.add(right_pane, weight=3)

        # Left pane contents
        self.create_left_pane(left_pane)
        
        # Right pane contents
        self.create_right_pane(right_pane)

    def create_left_pane(self, parent):
        # Connection Settings
        conn_frame = ttk.LabelFrame(parent, text="Connection Settings", padding=(10, 5))
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(conn_frame, text="Child IP:").grid(row=0, column=0, padx=5)
        self.ip_entry = ttk.Entry(conn_frame, width=18)
        self.ip_entry.insert(0, CHILD_IP)
        self.ip_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, padx=5)
        self.port_entry = ttk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, str(PORT))
        self.port_entry.grid(row=0, column=3, padx=5)
        
        self.update_config_btn = ttk.Button(conn_frame, text="Update Connection", 
                                          style='Green.TButton', command=self.update_connection)
        self.update_config_btn.grid(row=0, column=4, padx=5)
        
        self.ping_btn = ttk.Button(conn_frame, text="Ping Device", style='Green.TButton',
                                 command=self.ping_device)
        self.ping_btn.grid(row=0, column=5, padx=5)

        # Notebook
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Command Tab
        self.command_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.command_tab, text="Commands")
        self.setup_command_tab()
        
        # Sites Tab
        self.sites_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.sites_tab, text="Blocked Sites")
        self.setup_sites_tab()

        # Output Console
        output_frame = ttk.LabelFrame(parent, text="Console Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, 
                                                   font=('Consolas', 9), padx=10, pady=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)

    def create_right_pane(self, parent):
        # Screenshot Preview
        self.screenshot_frame = ttk.LabelFrame(parent, text="Live Preview", padding=10)
        self.screenshot_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Image display area
        self.screenshot_canvas = tk.Canvas(self.screenshot_frame, bg='white',
                                         borderwidth=0, highlightthickness=0)
        self.screenshot_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Preview controls
        control_frame = ttk.Frame(self.screenshot_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.screenshot_info = ttk.Label(control_frame, style='Status.TLabel')
        self.screenshot_info.pack(side=tk.LEFT)
        
        ttk.Button(control_frame, text="Take Screenshot", style='Green.TButton',
                 command=lambda: self.quick_command("GET_SCREENSHOT")).pack(side=tk.RIGHT)

        # Placeholder image
        self.show_placeholder()

    def show_placeholder(self):
        self.screenshot_canvas.delete("all")
        self.screenshot_canvas.create_text(self.screenshot_canvas.winfo_width()/2,
                                         self.screenshot_canvas.winfo_height()/2,
                                         text="No screenshot available\nClick button to capture",
                                         fill="#999", font=('Helvetica', 12))

    def update_screenshot_display(self, image):
        # Clear canvas
        self.screenshot_canvas.delete("all")
        
        # Calculate available space
        canvas_width = self.screenshot_canvas.winfo_width()
        canvas_height = self.screenshot_canvas.winfo_height()
        
        # Maintain aspect ratio
        img_width, img_height = image.size
        ratio = min(canvas_width/img_width, canvas_height/img_height)
        new_size = (int(img_width * ratio), int(img_height * ratio))
        
        # Resize image
        resized_img = image.resize(new_size, Image.Resampling.LANCZOS)
        tk_image = ImageTk.PhotoImage(resized_img)
        
        # Center image on canvas
        x = (canvas_width - new_size[0]) // 2
        y = (canvas_height - new_size[1]) // 2
        
        # Display image
        self.screenshot_canvas.create_image(x, y, anchor=tk.NW, image=tk_image)
        self.screenshot_canvas.image = tk_image  # Keep reference

    def poll_for_anomalies(self):
        while self.anomaly_polling_active:
            try:
                response = send_command("GET_ANOMALIES")
                if response.startswith("ANOMALY_ALERTS|") and "None" not in response:
                    alerts_data = response.split("ANOMALY_ALERTS|", 1)[1]
                    if alerts_data:
                        self.log_output(f"⚠️ ANOMALY DETECTED: {alerts_data}")
                        messagebox.showwarning("⚠️ Anomaly Detected", 
                                            f"Unusual activity detected:\n{alerts_data}")
                time.sleep(5)
            except Exception as e:
                time.sleep(5)
                pass

    def update_connection(self):
        try:
            new_ip = self.ip_entry.get().strip()
            new_port = int(self.port_entry.get().strip())
            
            if not all(part.isdigit() and 0 <= int(part) <= 255 for part in new_ip.split('.')):
                raise ValueError("Invalid IP address format")
                
            if not (1 <= new_port <= 65535):
                raise ValueError("Port must be between 1 and 65535")
                
            global CHILD_IP, PORT
            CHILD_IP = new_ip
            PORT = new_port
            self.status_var.set(f"Connection updated. Target: {CHILD_IP}:{PORT}")
            self.log_output(f"Connection settings updated to {CHILD_IP}:{PORT}")
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update connection: {e}")

    def ping_device(self):
        self.status_var.set(f"Pinging {CHILD_IP}:{PORT}...")
        self.update_idletasks()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((CHILD_IP, PORT))
                s.sendall("PING".encode('utf-8'))
                response = s.recv(1024).decode('utf-8', errors='replace')
                
                self.status_var.set(f"Connected to {CHILD_IP}:{PORT} - Response: {response}")
                self.log_output(f"Ping successful! Response: {response}")
        except socket.timeout:
            self.status_var.set(f"Connection timed out to {CHILD_IP}:{PORT}")
            self.log_output("Ping failed: Connection timed out")
        except ConnectionRefusedError:
            self.status_var.set(f"Connection refused by {CHILD_IP}:{PORT}")
            self.log_output("Ping failed: Connection refused (server not running)")
        except Exception as e:
            self.status_var.set(f"Connection error: {e}")
            self.log_output(f"Ping failed: {e}")

    def update_param_fields(self, event=None):
        for widget in self.param_frame.winfo_children():
            widget.destroy()

        selected_command = self.command_var.get()
        args = COMMAND_ARGS.get(selected_command, [])
        self.param_entries = {}
        for idx, arg in enumerate(args):
            ttk.Label(self.param_frame, text=f"{arg}:").grid(row=idx, column=0, padx=5, pady=2)
            entry = ttk.Entry(self.param_frame, width=40)
            entry.grid(row=idx, column=1, padx=5, pady=2)
            self.param_entries[arg] = entry

    def quick_command(self, command):
        self.log_output(f"> Sending quick command: {command}")
        self.status_var.set(f"Sending {command} to {CHILD_IP}:{PORT}...")
        threading.Thread(target=self._send_command_thread, args=(command,), daemon=True).start()

    def send_command_gui(self):
        selected_command = self.command_var.get()
        if not selected_command:
            messagebox.showerror("Error", "Please select a command.")
            return

        command_parts = [selected_command]
        for arg in COMMAND_ARGS[selected_command]:
            value = self.param_entries[arg].get().strip()
            if not value:
                messagebox.showerror("Error", f"Please enter a value for '{arg}'.")
                return
            command_parts.append(value)

        full_command = DELIMITER.join(command_parts)
        self.log_output(f"> Sending: {full_command}")
        self.status_var.set(f"Sending command to {CHILD_IP}:{PORT}...")

        self.send_button.config(text="Sending...", state=tk.DISABLED)
        self.update_idletasks()
        
        threading.Thread(target=self._send_command_thread, args=(full_command,), daemon=True).start()

    def _send_command_thread(self, command):
        try:
            response = send_command(command)
            self.after(0, lambda: self.process_response(response))
        except Exception as e:
            self.after(0, lambda: self.log_output(f"Error: {e}"))
        finally:
            self.after(0, lambda: self.send_button.config(text="Send Command", state=tk.NORMAL))
            self.after(0, lambda: self.status_var.set(f"Ready. Target: {CHILD_IP}:{PORT}"))

    def process_response(self, response):
        if response.startswith("SCREENSHOT|"):
            try:
                img_data = response.split("SCREENSHOT|", 1)[1].strip().replace('\n', '')
                padding = len(img_data) % 4
                if padding != 0:
                    img_data += "=" * (4 - padding)

                img_bytes = base64.b64decode(img_data)
                image = Image.open(BytesIO(img_bytes))
                self.current_screenshot = image

                timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                filename = f"screenshots/ss_{timestamp}.png"
                image.save(filename)

                # Update display
                self.update_screenshot_display(image)
                self.screenshot_info.config(text=f"Last captured: {timestamp}")
                self.log_output(f"[Screenshot received and saved to {filename}]")

            except Exception as e:
                self.log_output(f"[Error decoding screenshot: {e}]")
                self.show_placeholder()
        
        elif response.startswith("BLOCKED_SITES|"):
            sites_data = response.split("BLOCKED_SITES|", 1)[1]
            self.blocked_sites = sites_data.split(",") if sites_data and sites_data != "None" else []
            self.update_sites_listbox()
            self.log_output(f"Received list of {len(self.blocked_sites)} blocked sites" if self.blocked_sites else "No blocked sites found")
        
        elif response.startswith("APPS|"):
            apps_data = response.split("APPS|", 1)[1]
            apps_list = apps_data.split(",")
            self.log_output(f"Running Apps: {', '.join(apps_list)}")
        
        else:
            self.log_output(f"Response: {response}")
            if response.startswith(("BLOCKED|", "UNBLOCKED|", "BLOCK_FAILED|", "UNBLOCK_FAILED|")):
                self.after(500, self.refresh_blocked_sites)

    def log_output(self, message):
        self.output_text.config(state=tk.NORMAL)
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.output_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def block_site(self):
        site = self.site_entry.get().strip()
        if not site:
            messagebox.showerror("Error", "Please enter a website to block.")
            return
        
        command = f"BLOCK_SITE{DELIMITER}{site}"
        self.log_output(f"> Blocking site: {site}")
        threading.Thread(target=self._send_command_thread, args=(command,), daemon=True).start()
        self.site_entry.delete(0, tk.END)
    
    def unblock_selected_site(self):
        selected_idx = self.sites_listbox.curselection()
        if not selected_idx:
            messagebox.showerror("Error", "Please select a site to unblock.")
            return
        
        site = self.sites_listbox.get(selected_idx[0])
        command = f"UNBLOCK_SITE{DELIMITER}{site}"
        self.log_output(f"> Unblocking site: {site}")
        threading.Thread(target=self._send_command_thread, args=(command,), daemon=True).start()
    
    def refresh_blocked_sites(self):
        command = "GET_BLOCKED_SITES"
        self.log_output("> Refreshing blocked sites list...")
        threading.Thread(target=self._send_command_thread, args=(command,), daemon=True).start()
    
    def update_sites_listbox(self):
        self.sites_listbox.delete(0, tk.END)
        for site in self.blocked_sites:
            self.sites_listbox.insert(tk.END, site)

    def setup_command_tab(self):
        cmd_frame = ttk.Frame(self.command_tab)
        cmd_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Command Controls
        control_frame = ttk.LabelFrame(cmd_frame, text="Command Center", padding=10)
        control_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(control_frame, text="Select Command:", style='Header.TLabel').pack(side=tk.LEFT)
        self.command_var = tk.StringVar()
        self.command_box = ttk.Combobox(control_frame, textvariable=self.command_var, 
                                      values=list(COMMAND_ARGS.keys()), state="readonly")
        self.command_box.pack(side=tk.LEFT, padx=10)
        self.command_box.bind("<<ComboboxSelected>>", self.update_param_fields)

        self.param_frame = ttk.Frame(control_frame)
        self.param_frame.pack(fill=tk.X, pady=10)

        self.send_button = ttk.Button(control_frame, text="Send Command", style='Green.TButton',
                                   command=self.send_command_gui)
        self.send_button.pack(side=tk.RIGHT, padx=5)

        # Quick Actions
        quick_frame = ttk.LabelFrame(cmd_frame, text="Quick Actions", padding=10)
        quick_frame.pack(fill=tk.X, pady=5)
        
        self.screenshot_btn = ttk.Button(quick_frame, text="Take Screenshot", 
                                       command=lambda: self.quick_command("GET_SCREENSHOT"))
        self.screenshot_btn.pack(side=tk.LEFT, padx=5)
        
        self.apps_btn = ttk.Button(quick_frame, text="Get Running Apps",
                                 command=lambda: self.quick_command("GET_RUNNING_APPS"))
        self.apps_btn.pack(side=tk.LEFT, padx=5)
        
        self.lock_btn = ttk.Button(quick_frame, text="Lock Screen", style='Red.TButton',
                                 command=lambda: self.quick_command("LOCK_SCREEN"))
        self.lock_btn.pack(side=tk.LEFT, padx=5)
        
        self.anomalies_btn = ttk.Button(quick_frame, text="Check Anomalies",
                                      command=lambda: self.quick_command("GET_ANOMALIES"))
        self.anomalies_btn.pack(side=tk.LEFT, padx=5)

    def setup_sites_tab(self):
        main_frame = ttk.Frame(self.sites_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Site Management
        manage_frame = ttk.LabelFrame(main_frame, text="Site Management", padding=10)
        manage_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(manage_frame, text="Website:", style='Header.TLabel').grid(row=0, column=0, sticky="w")
        self.site_entry = ttk.Entry(manage_frame, width=40)
        self.site_entry.grid(row=0, column=1, padx=5, sticky="ew")
        
        btn_frame = ttk.Frame(manage_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")
        
        self.block_btn = ttk.Button(btn_frame, text="Block Website", style='Green.TButton',
                                  command=self.block_site)
        self.block_btn.pack(side=tk.LEFT, padx=5)
        
        self.unblock_btn = ttk.Button(btn_frame, text="Unblock Selected", style='Red.TButton',
                                    command=self.unblock_selected_site)
        self.unblock_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_btn = ttk.Button(btn_frame, text="Refresh List", 
                                   command=self.refresh_blocked_sites)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # Blocked Sites List
        list_frame = ttk.LabelFrame(manage_frame, text="Currently Blocked Sites", padding=10)
        list_frame.grid(row=2, column=0, columnspan=2, sticky="nsew")
        manage_frame.rowconfigure(2, weight=1)
        
        self.sites_listbox = tk.Listbox(list_frame, background='white', 
                                      selectbackground='#3498db', selectforeground='white',
                                      font=('Helvetica', 10))
        self.sites_listbox.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.sites_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.sites_listbox.config(yscrollcommand=scrollbar.set)


if __name__ == "__main__":
    app = NetGuardianGUI()
    app.mainloop()