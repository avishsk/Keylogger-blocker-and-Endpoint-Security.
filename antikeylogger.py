import tkinter as tk
from tkinter import messagebox, scrolledtext
import psutil
import subprocess
import json
import threading
import time


# Global flag to control continuous scanning
is_scanning = False

# Define the port to block
blocked_port = 587

# Define the file to store the whitelisted processes
whitelist_file = "whitelist.json"

# Define the file to store the blacklisted processes
blacklist_file = "blacklist.json"

# Load the whitelisted processes from the file
try:
    with open(whitelist_file, "r") as f:
        whitelisted_processes = json.load(f)
except FileNotFoundError:
    whitelisted_processes = []

# Load the blacklisted processes from the file
try:
    with open(blacklist_file, "r") as f:
        blacklisted_processes = json.load(f)
except FileNotFoundError:
    blacklisted_processes = []

def find_suspicious_background_processes():
    suspicious_processes = []
    for process in psutil.process_iter(attrs=['pid', 'name']):
        process_name = process.info['name'].lower()
        suspicious_keywords = ["keylogger.exe", "malware.exe", "spyware.exe", "hacker_tool.exe", "kelogSMTP.exe", "kelogsmtp.exe"]
        for keyword in suspicious_keywords:
            if keyword in process_name:
                suspicious_processes.append(process)
                break
    return suspicious_processes

def terminate_suspicious_processes(suspicious_processes):
    for process in suspicious_processes:
        try:
            process.terminate()
            action_feedback.insert(tk.END, f"Terminated suspicious process: PID {process.info['pid']} - Name: {process.info['name']}\n")
        except Exception as e:
            action_feedback.insert(tk.END, f"Error terminating suspicious process: {e}\n")

def find_process_using_port(port):
    proc = subprocess.Popen(f"netstat -ano -p tcp | findStr {port}", shell=True, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    out, err = proc.communicate()
    process_info = out.decode().strip().split()[-1] if out else None
    return process_info

def prompt_user(process_info):
    process_id = int(process_info.split()[0])
    try:
        process = psutil.Process(process_id)
        process_name = process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        process_name = "Unknown"

    prompt_window = tk.Toplevel()
    prompt_window.title("Process Detected")
    label = tk.Label(prompt_window, text=f"Potential keylogger found: {process_name}. Do you want to whitelist or blacklist this process?")
    label.pack()

    whitelist_button = tk.Button(prompt_window, text="Whitelist", command=lambda: handle_whitelist(process_name, prompt_window))
    whitelist_button.pack()

    blacklist_button = tk.Button(prompt_window, text="Blacklist", command=lambda: handle_blacklist(process_id, process_name, prompt_window))
    blacklist_button.pack()

def handle_whitelist(process_name, prompt_window):
    whitelisted_processes.append(process_name)
    action_feedback.insert(tk.END, f"Process whitelisted: {process_name}\n")
    with open(whitelist_file, "w") as f:
        json.dump(whitelisted_processes, f)
    prompt_window.destroy()

def handle_blacklist(process_id, process_name, prompt_window):
    if process_name not in blacklisted_processes:
        blacklisted_processes.append(process_name)
        with open(blacklist_file, "w") as f:
            json.dump(blacklisted_processes, f)
        action_feedback.insert(tk.END, f"Process blacklisted: {process_name}\n")
    try:
        psutil.Process(process_id).terminate()
        action_feedback.insert(tk.END, f"Terminated and blacklisted process: PID {process_id} - Name: {process_name}\n")
    except Exception as e:
        action_feedback.insert(tk.END, f"Error terminating process: {e}\n")
    prompt_window.destroy()

def scan_for_keyloggers(scan_mode, status_label):
    global is_scanning
    if not is_scanning and scan_mode == "Manual":
        is_scanning = True  # Allow manual scan even when continuous scan is not active
    if not is_scanning:
        return
    suspicious_processes = find_suspicious_background_processes()
    if suspicious_processes:
        terminate_suspicious_processes(suspicious_processes)
    process_using_port = find_process_using_port(blocked_port)
    if process_using_port:
        process_id = int(process_using_port.split()[0])
        try:
            process = psutil.Process(process_id)
            process_name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = "Unknown"
        if process_name in blacklisted_processes:
            try:
                process.terminate()
                action_feedback.insert(tk.END, f"\nAutomatically terminated blacklisted process: {process_name}\n")
            except Exception as e:
                action_feedback.insert(tk.END, f"Error automatically terminating blacklisted process: {e}\n")
        elif process_name not in whitelisted_processes:
            prompt_user(process_using_port)
    else:
        status_label.config(text="Status: No keyloggers found.")
    if scan_mode == "Manual":
        is_scanning = False  # Stop scanning after one cycle for manual scan
    if scan_mode == "Continuous" and is_scanning:
        threading.Timer(5, lambda: scan_for_keyloggers(scan_mode, status_label)).start()

def monitor_usb_insertion():
    previous_usb_drives = set()
    while True:
        current_usb_drives = set()
        for partition in psutil.disk_partitions():
            if "removable" in partition.opts:
                current_usb_drives.add(partition.device)
        new_drives = current_usb_drives - previous_usb_drives
        if new_drives:
            for drive_letter in new_drives:
                disable_autorun(drive_letter)
                scan_usb_drive(drive_letter)
        previous_usb_drives = current_usb_drives
        time.sleep(2)

def disable_autorun(drive_letter):
    try:
        subprocess.run(["REG", "ADD", f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                        "/v", "NoDriveTypeAutoRun", "/t", "REG_DWORD", "/d", "255", "/f"], check=True)
        action_feedback.insert(tk.END, f"Disabled autorun for {drive_letter}\n")
    except subprocess.CalledProcessError as e:
        action_feedback.insert(tk.END, f"Error disabling autorun for {drive_letter}: {e}\n")

def scan_usb_drive(drive_letter):
    try:
        result = subprocess.run(["clamscan", "-r", drive_letter], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        scan_output = result.stdout.decode() + result.stderr.decode()
        action_feedback.insert(tk.END, f"USB scan result for {drive_letter}:\n{scan_output}\n")
    except subprocess.CalledProcessError as e:
        action_feedback.insert(tk.END, f"Error scanning USB drive {drive_letter}: {e}\n")

def stop_scanning():
    global is_scanning
    is_scanning = False
    status_label.config(text="Status: Scanning stopped.")
    stop_scan_button.config(state="disabled")

def start_continuous_scan(scan_mode, status_label):
    global is_scanning
    if not is_scanning:
        is_scanning = True
        status_label.config(text="Status: Continuous scanning...")
        stop_scan_button.config(state="normal")
        threading.Thread(target=lambda: scan_for_keyloggers(scan_mode, status_label), daemon=True).start()

# GUI setup
root = tk.Tk()
root.title("Keylogger Detection Tool")

def manual_scan():
    global is_scanning
    is_scanning = False  # Ensure continuous scanning is stopped for manual scan
    scan_for_keyloggers("Manual", status_label)

manual_scan_button = tk.Button(root, text="Manual Scan", command=manual_scan)
manual_scan_button.pack()

def continuous_scan_start():
    start_continuous_scan("Continuous", status_label)

continuous_scan_button = tk.Button(root, text="Continuous Scan", command=continuous_scan_start)
continuous_scan_button.pack()

stop_scan_button = tk.Button(root, text="Stop Scanning", command=stop_scanning, state="disabled")
stop_scan_button.pack()

status_label = tk.Label(root, text="Status: Idle")
status_label.pack()

action_feedback = scrolledtext.ScrolledText(root, height=10)
action_feedback.pack()

# Start USB monitoring in a separate thread
threading.Thread(target=monitor_usb_insertion, daemon=True).start()
root.mainloop()
