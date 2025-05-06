#!/usr/bin/env python3
import socket
import threading
import time
import random
import os
import json
import base64
from datetime import datetime
from io import BytesIO
from PIL import ImageGrab  # Ensure Pillow is installed

# Server config
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5500
DELIMITER = '|'
MAX_BUFFER_SIZE = 1024 * 1024 * 10  # 10MB for screenshots

child_state = {
    'blocked_sites': [],
    'time_limits': {},
    'reported_anomalies': set()
}
anomaly_alerts = []

LOG_FILE = "logs.txt"
BLOCKED_FILE = "blocked_sites.txt"
CONFIG_FILE = "config.json"
SCREENSHOT_DIR = "screenshots"

# Ensure directories exist
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

def log(msg):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {msg}\n")
    print(f"[{timestamp}] {msg}")

def save_blocked_sites():
    """Save blocked sites to file"""
    try:
        with open(BLOCKED_FILE, 'w') as f:
            json.dump(child_state['blocked_sites'], f)
    except Exception as e:
        log(f"Error saving blocked sites: {e}")

def load_blocked_sites():
    """Load blocked sites from file"""
    try:
        if os.path.exists(BLOCKED_FILE):
            with open(BLOCKED_FILE, 'r') as f:
                child_state['blocked_sites'] = json.load(f)
            log(f"Loaded {len(child_state['blocked_sites'])} blocked sites")
    except Exception as e:
        log(f"Error loading blocked sites: {e}")

def clean_site_name(site):
    """Standardize site name format"""
    if not site:
        return ""
    
    # Clean up the site name
    site = site.lower().strip()
    if not site.startswith(('http://', 'https://')):
        site = site.split('/')[0]  # Get domain only
    else:
        site = site.split('//')[1].split('/')[0]  # Remove protocol and path
    
    # Remove www. if present
    if site.startswith('www.'):
        site = site[4:]
    
    return site

def block_site(site):
    """Actually block a site by modifying hosts file"""
    site = clean_site_name(site)
    if not site:
        return False
    
    try:
        hosts_path = ""
        if os.name == 'nt':  # Windows
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        else:  # Linux/Mac
            hosts_path = '/etc/hosts'
            
        # Check if we have permission to modify hosts
        if not os.access(hosts_path, os.W_OK):
            log(f"No permission to modify hosts file: {hosts_path}")
            return False
            
        # Read current hosts file
        with open(hosts_path, 'r') as f:
            content = f.readlines()
            
        # Check if site is already blocked
        block_entries = [
            f"127.0.0.1 {site}\n",
            f"127.0.0.1 www.{site}\n"
        ]
        
        if any(entry in content for entry in block_entries):
            log(f"Site {site} is already blocked in hosts file")
            
        # Append site to hosts file
        with open(hosts_path, 'a') as f:
            f.write(f"\n127.0.0.1 {site}\n127.0.0.1 www.{site}\n")
            
        log(f"Successfully blocked site: {site}")
        return True
    except Exception as e:
        log(f"Error blocking site: {e}")
        return False

def unblock_site(site):
    """Remove site from hosts file to unblock it"""
    site = clean_site_name(site)
    if not site:
        return False
    
    try:
        hosts_path = ""
        if os.name == 'nt':  # Windows
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        else:  # Linux/Mac
            hosts_path = '/etc/hosts'
            
        # Check if we have permission to modify hosts
        if not os.access(hosts_path, os.W_OK):
            log(f"No permission to modify hosts file: {hosts_path}")
            return False
            
        # Read current hosts file
        with open(hosts_path, 'r') as f:
            lines = f.readlines()
            
        # Filter out the lines containing our site
        new_lines = []
        site_removed = False
        for line in lines:
            if f"127.0.0.1 {site}" not in line and f"127.0.0.1 www.{site}" not in line:
                new_lines.append(line)
            else:
                site_removed = True
        
        # Write back the filtered hosts file
        if site_removed:
            with open(hosts_path, 'w') as f:
                f.writelines(new_lines)
            log(f"Successfully unblocked site: {site}")
            return True
        else:
            log(f"Site {site} was not found in hosts file")
            return True  # Return true anyway since the site is not blocked
    except Exception as e:
        log(f"Error unblocking site: {e}")
        return False

def get_running_apps():
    """Get list of running user applications (not services)"""
    try:
        running_apps = []
        
        if os.name == 'nt':  # Windows
            import psutil
            # Focus on user applications with visible windows
            for proc in psutil.process_iter(['name', 'exe', 'username', 'pid']):
                try:
                    process_info = proc.info
                    process_name = process_info['name']
                    
                    # Common apps have windows - use this as a filter
                    if process_name.endswith(('.exe', '.EXE')):
                        # Get only user apps, not system services
                        username = process_info.get('username')
                        if (username and 
                            'SYSTEM' not in username.upper() and
                            'LOCAL SERVICE' not in username.upper() and
                            'NETWORK SERVICE' not in username.upper()):
                            
                            # Clean up the name by removing .exe
                            app_name = process_name
                            if app_name.lower().endswith('.exe'):
                                app_name = app_name[:-4]
                                
                            if app_name not in running_apps:
                                running_apps.append(app_name)
                except:
                    pass
                    
        else:  # Linux/Mac
            import subprocess
            try:
                # For Mac/Linux: get graphical applications
                current_user = os.environ.get('USER', '')
                
                if 'darwin' in os.sys.platform:  # macOS
                    result = subprocess.check_output(['ps', '-cxo', 'command']).decode('utf-8')
                    for line in result.split('\n'):
                        if line and '/' in line and not line.startswith('/'):
                            app_name = line.split('/')[-1].split(' ')[0]
                            if app_name and app_name not in running_apps:
                                running_apps.append(app_name)
                else:  # Linux
                    # Try to get X11 window applications
                    try:
                        result = subprocess.check_output(['ps', '-u', current_user, '-o', 'comm=']).decode('utf-8')
                        for line in result.split('\n'):
                            if line.strip() and not line.startswith('/'):
                                app_name = line.strip()
                                if app_name and app_name not in running_apps:
                                    running_apps.append(app_name)
                    except:
                        # Fallback method
                        result = subprocess.check_output(['ps', 'aux']).decode('utf-8')
                        for line in result.split('\n')[1:]:  # Skip header
                            if line.strip() and current_user in line:
                                parts = line.split()
                                if len(parts) > 10:
                                    cmd = parts[10]
                                    if cmd and '/' in cmd:
                                        app_name = cmd.split('/')[-1]
                                        if app_name and app_name not in running_apps:
                                            running_apps.append(app_name)
            except Exception as e:
                log(f"Error getting user apps: {e}")
                running_apps = ["Error: could not determine running apps"]
        
        # Additional filtering of common system processes
        system_processes = {
            "svchost", "system", "smss", "csrss", "wininit", 
            "services", "lsass", "winlogon", "spoolsv", 
            "explorer", "dwm", "taskhost", "conhost", "rundll32",
            "fontdrvhost", "runtimebroker", "dllhost", "ctfmon",
            "taskhostw", "sihost", "registry", "devenv", "werfault",
            "shellexperiencehost", "applicationframehost", "systemsettings",
            "smartscreen", "securityhealthservice", "searchindexer", 
            "searchui", "searchapp", "startmenuexperiencehost"
        }
        
        running_apps = [app for app in running_apps if app.lower() not in system_processes]
        running_apps = sorted(list(set(running_apps)))
        return running_apps[:30]  # Limit to 30 apps
        
    except Exception as e:
        log(f"Error getting running apps: {e}")
        return ["Error fetching apps"]

def anomaly_detection_thread():
    """Simulate anomaly detection with duplicate prevention"""
    while True:
        time.sleep(10)
        if child_state['blocked_sites'] and random.random() < 0.2:
            site = random.choice(child_state['blocked_sites'])
            alert_key = f"blocked_site_access:{site}"
            
            # Only report if this exact anomaly hasn't been reported yet
            if alert_key not in child_state['reported_anomalies']:
                alert = f"Blocked site access attempt: {site}"
                anomaly_alerts.append(alert)
                child_state['reported_anomalies'].add(alert_key)
                log(f"ANOMALY_DETECTED:{alert}")

def capture_screenshot_base64():
    """Capture screenshot and return as base64 string"""
    try:
        img = ImageGrab.grab()
        buffer = BytesIO()
        img.save(buffer, format="PNG", optimize=True)  # Optimize for size
        img_bytes = buffer.getvalue()
        encoded = base64.b64encode(img_bytes).decode('ascii')
        log(f"Screenshot captured: {len(encoded)} bytes")
        return encoded
    except Exception as e:
        log(f"Screenshot failed: {e}")
        return f"ERROR|Screenshot failed: {e}"

def lock_screen_thread():
    """Lock screen in a separate thread to avoid blocking"""
    try:
        import ctypes
        ctypes.windll.user32.LockWorkStation()
        log("Screen locked successfully")
        return True
    except Exception as e:
        log(f"Lock screen failed: {e}")
        return False

def process_command(command_str):
    """Process incoming commands"""
    def display_chat_popup(message):
        try:
            # Use threading to avoid blocking
            def show_popup():
                import tkinter as tk
                from tkinter import messagebox
                
                # Create a root window but keep it hidden
                root = tk.Tk()
                root.withdraw()
                
                # Show the chat message in a popup
                messagebox.showinfo("Message from Parent", message)
                
                # Destroy the root window after showing the message
                root.destroy()
            
            # Start in a new thread to avoid blocking
            popup_thread = threading.Thread(target=show_popup)
            popup_thread.daemon = True
            popup_thread.start()
            
            log(f"Chat popup displayed: {message}")
            return True
        except Exception as e:
            log(f"Failed to display chat popup: {e}")
            return False
    parts = command_str.strip().split(DELIMITER)
    command = parts[0].upper()
    log(f"Processing command: {command}")

    try:
        # Handle ping command (for connection testing)
        if command == "PING":
            return "PONG|NetGuardian Child is running"
            
        if command == "BLOCK_SITE":
            site = parts[1]
            site_clean = clean_site_name(site)
            if site_clean not in child_state['blocked_sites']:
                child_state['blocked_sites'].append(site_clean)
                save_blocked_sites()
                success = block_site(site_clean)
                if success:
                    return f"BLOCKED|{site_clean}"
                else:
                    return f"BLOCK_FAILED|{site_clean}|Permission denied or error occurred"
            return f"ALREADY_BLOCKED|{site_clean}"
            
        elif command == "UNBLOCK_SITE":
            site = parts[1]
            site_clean = clean_site_name(site)
            if site_clean in child_state['blocked_sites']:
                child_state['blocked_sites'].remove(site_clean)
                save_blocked_sites()
                success = unblock_site(site_clean)
                if success:
                    return f"UNBLOCKED|{site_clean}"
                else:
                    return f"UNBLOCK_FAILED|{site_clean}|Permission denied or error occurred"
            return f"NOT_BLOCKED|{site_clean}"

        elif command == "GET_BLOCKED_SITES":
            if child_state['blocked_sites']:
                sites = ",".join(child_state['blocked_sites'])
                return f"BLOCKED_SITES|{sites}"
            return "BLOCKED_SITES|None"

        elif command == "GET_RUNNING_APPS":
            apps = get_running_apps()
            return "APPS|" + ",".join(apps)

        elif command == "LOCK_SCREEN":
            # Start lock screen in a separate thread to avoid blocking
            thread = threading.Thread(target=lock_screen_thread)
            thread.daemon = True
            thread.start()
            
            # Return immediately - don't wait for lock
            return "SCREEN_LOCK_INITIATED"

        elif command == "CHAT":
            message = parts[1] if len(parts) > 1 else "No message"
            display_success = display_chat_popup(message)
            if display_success:
                return f"CHAT_ACK|Received and displayed: {message}"
            else:
                return f"CHAT_ACK|Received but display failed: {message}"

        elif command == "TIME_FILTER":
            site, duration = parts[1], parts[2]
            child_state['time_limits'][site] = duration
            log(f"Time filter set: {site} for {duration}")
            return f"TIME_FILTER_SET|{site}|{duration}"

        elif command == "GET_SCREENSHOT":
            base64_img = capture_screenshot_base64()
            if isinstance(base64_img, str) and base64_img.startswith("ERROR"):
                return base64_img
            return f"SCREENSHOT|{base64_img}"

        elif command == "GET_ANOMALIES":
            if anomaly_alerts:
                alerts = "\n".join(anomaly_alerts)
                anomaly_alerts.clear()
                return f"ANOMALY_ALERTS|{alerts}"
            return "ANOMALY_ALERTS|None"

        # else:
        #     return f"UNKNOWN_COMMAND|{command}"

    except Exception as e:
        log(f"Error processing command: {e}")
        return f"ERROR|{str(e)}"

def handle_client(conn, addr):
    """Handle client connection"""
    log(f"Connection from {addr}")
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_BUFFER_SIZE:
                log(f"Data from {addr} exceeded maximum size")
                break
            # If we have a complete command, process it
            if b'\n' in data or len(data) > 0:  # Commands are generally small
                break
        
        if data:
            command = data.decode('utf-8', errors='replace').strip()
            log(f"Received command from {addr}: {command[:50]}...")
            response = process_command(command)
            
            # Send response in chunks if large
            total_sent = 0
            response_bytes = response.encode('utf-8')
            bytes_to_send = len(response_bytes)
            
            while total_sent < bytes_to_send:
                sent = conn.send(response_bytes[total_sent:total_sent + 4096])
                if sent == 0:
                    raise RuntimeError("Socket connection broken")
                total_sent += sent
            
            log(f"Response sent to {addr}: {len(response_bytes)} bytes")
    except Exception as e:
        log(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        log(f"Connection closed with {addr}")

def start_server():
    """Start the server"""
    log("Starting NetGuardian Child Server")
    load_blocked_sites()
    
    # Re-apply blocking for all sites in the list
    for site in child_state['blocked_sites']:
        block_site(site)
    
    # Start anomaly detection thread
    threading.Thread(target=anomaly_detection_thread, daemon=True).start()
    log("Anomaly detection thread started")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((HOST, PORT))
            s.listen(5)
            log(f"Server listening on {HOST}:{PORT}")
            
            while True:
                try:
                    conn, addr = s.accept()
                    log(f"New connection from {addr}")
                    client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    log(f"Error accepting connection: {e}")
                    time.sleep(1)  # Prevent CPU spinning on repeated errors
                    
        except Exception as e:
            log(f"Server error: {e}")
            
if __name__== "__main__":start_server()
