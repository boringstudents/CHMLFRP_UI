import ast
import logging
import os
import shutil
import subprocess
import sys
import time
import zipfile
from logging.handlers import *
import random
import socket
import winreg
from datetime import datetime
import threading
import json
from concurrent.futures import *
import ipaddress
import re
import traceback

import requests
from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *
from mcstatus import *
from requests import *
import psutil
import pyperclip

# 程序信息
APP_NAME = "CHMLFRP_UI" # 程序名称
APP_VERSION = "1.5.2" # 程序版本
PY_VERSION = "3.13.1" # Python 版本
WINDOWS_VERSION = "Windows NT 10.0" # 系统版本
Number_of_tunnels = 0 # 隧道数量

def get_absolute_path(relative_path):
    return os.path.abspath(os.path.join(os.path.split(sys.argv[0])[0], relative_path))

# 从配置文件加载日志设置
try:
    settings_path = get_absolute_path("settings.json")
    if os.path.exists(settings_path):
        with open(settings_path, 'r') as f:
            settings = json.load(f)
            maxBytes = settings.get('log_size_mb', 10) * 1024 * 1024  # 默认10MB
            backupCount = settings.get('backup_count', 30)  # 默认30个备份
    else:
        maxBytes = 10 * 1024 * 1024  # 默认10MB
        backupCount = 30  # 默认30个备份
except Exception as e:
    print(f"加载日志设置失败: {str(e)}")
    maxBytes = 10 * 1024 * 1024  # 默认10MB
    backupCount = 30  # 默认30个备份

# 生成统一的 User-Agent
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Python/{PY_VERSION}; {WINDOWS_VERSION})"

# 生成统一的请求头
def get_headers(json=False):
    """
    获取统一的请求头
    Args:
        json: 是否添加 Content-Type: application/json
    Returns:
        dict: 请求头字典
    """
    headers = {'User-Agent': USER_AGENT}
    if json:
        headers['Content-Type'] = 'application/json'
    return headers

# 设置全局日志
logger = logging.getLogger('CHMLFRP_UI')
logger.setLevel(logging.DEBUG)
file_handler = RotatingFileHandler('CHMLFRP_UI.log', maxBytes=maxBytes, backupCount=backupCount)
file_handler.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


def is_valid_domain(domain):
    """IPV4格式检测"""
    pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$')
    return bool(pattern.match(domain))


def is_valid_ipv4(ip):
    """IPV4数字检测"""
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
    except ValueError:
        return False


def is_valid_ipv6(ip):
    """IPV6检测"""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def remove_http_https(url):
    """htpp头去除"""
    return re.sub(r'^https?://', '', url)


def parse_srv_target(target):
    """srv解析操作"""
    parts = target.split()
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    return None, None, None, target


def validate_port(port):
    """端口检查"""
    try:
        port_num = int(port)
        return 0 < port_num <= 65535
    except ValueError:
        return False


def get_nodes(max_retries=3, retry_delay=1):
    """获取节点数据"""
    url = "http://cf-v2.uapis.cn/node"
    headers = get_headers()

    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if data['code'] == 200:
                return data['data']
            else:
                logger.error(f"获取节点数据失败: {data['msg']}")
                return []
        except RequestException as e:
            logger.warning(f"获取节点数据时发生网络错误 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
            else:
                logger.error("获取节点数据失败，已达到最大重试次数")
                return []
        except Exception:
            logger.exception("获取节点数据时发生未知错误")
            return []


def login(username, password):
    """用户登录返回token"""
    logger.info(f"尝试登录用户: {username}")
    url = f"http://cf-v2.uapis.cn/login"
    params = {
        "username": username,
        "password": password
    }
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, params=params)
        response_data = response.json()
        token = response_data.get("data", {}).get("usertoken")
        if token:
            logger.info("登录成功")
        else:
            logger.warning("登录失败")
        return token
    except Exception as e:
        logger.exception("登录时发生错误")
        logger.exception(e)
        return None


def resolve_to_ipv4(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_user_tunnels(token):
    """获取用户隧道列表"""
    url = f"http://cf-v2.uapis.cn/tunnel"
    params = {
        "token": token
    }
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if data['code'] == 200:
            tunnels = data.get("data", [])
            return tunnels
        else:
            logger.error(f" {data.get('msg')}")
            return []

    except requests.RequestException:
        logger.exception("获取隧道列表时发生网络错误")
        return []
    except Exception:
        logger.exception("获取隧道列表时发生未知错误")
        return []


def get_node_ip(token, node):
    """获取节点IP"""
    logger.info(f"获取节点 {node} 的IP")
    url = f"http://cf-v2.uapis.cn/nodeinfo"
    params = {
        "token": token,
        "node": node
    }
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, params=params)
        ip = response.json()["data"]["realIp"]
        logger.info(f"节点 {node} 的IP为 {ip}")
        return ip
    except Exception as e:
        logger.exception(f"获取节点 {node} 的IP时发生错误")
        logger.exception(e)
        return None


def update_subdomain(token, domain, record, target, record_type):
    """更新子域名"""
    logger.info(f"更新子域名 {record}.{domain} 到 {target}")
    url = "http://cf-v2.uapis.cn/update_free_subdomain"
    payload = {
        "token": token,
        "domain": domain,
        "record": record,
        "type": record_type,
        "target": target,
        "ttl": "1分钟",
        "remarks": ""
    }
    headers = get_headers(json=True)
    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            logger.info("子域名更新成功")
        else:
            logger.warning(f"子域名更新失败: {response.text}")
    except Exception as e:
        logger.exception("更新子域名时发生错误")
        logger.exception(e)

def update_tunnel(token, tunnel_info, node):
    """更新隧道信息"""
    logger.info(f"更新隧道 {tunnel_info['name']} 到节点 {node}")
    url = "http://cf-v2.uapis.cn/update_tunnel"
    payload = {
        "tunnelid": int(tunnel_info["id"]),
        "token": token,
        "tunnelname": tunnel_info["name"],
        "node": str(node),
        "localip": tunnel_info["localip"],
        "porttype": tunnel_info["type"],
        "localport": tunnel_info["nport"],
        "remoteport": tunnel_info["dorp"],
        "banddomain": "",
        "encryption": tunnel_info["encryption"],
        "compression": tunnel_info["compression"],
        "extraparams": ""
    }

    headers = get_headers(json=True)
    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            logger.info("隧道更新成功")
        else:
            logger.warning(f"隧道更新失败: {response.text}")
    except Exception as e:
        logger.exception("更新隧道时发生错误")
        logger.exception(e)


def is_node_online(node_name):
    url = "http://cf-v2.uapis.cn/node_stats"
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()
            if stats and 'data' in stats:
                for node in stats['data']:
                    if node['node_name'] == node_name:
                        return node['state'] == "online"
        return False
    except Exception:
        logger.exception("检查节点在线状态时发生错误")
        return False

def parse_domain(domain):
    """解析域名"""
    logger.info(f"解析域名: {domain}")
    parts = domain.split('.')
    if len(parts) >= 3:
        subdomain = '.'.join(parts[:-2])
        main_domain = '.'.join(parts[-2:])
    else:
        subdomain = parts[0]
        main_domain = '.'.join(parts[-2:])
    logger.debug(f"解析结果 - 子域名: {subdomain}, 主域名: {main_domain}")
    return subdomain, main_domain


class QtHandler(QObject, logging.Handler):
    """Qt日志处理器"""
    new_record = pyqtSignal(str)

    def __init__(self, parent):
        super(QtHandler, self).__init__(parent)  # 只调用一次 super()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.setFormatter(formatter)

    def emit(self, record):
        msg = self.format(record)
        self.new_record.emit(msg)


def setup_logging(parent):
    """设置日志系统"""
    logger = logging.getLogger('CHMLFRP_UI')
    logger.setLevel(logging.DEBUG)

    file_handler = RotatingFileHandler('CHMLFRP_UI.log', maxBytes=maxBytes, backupCount=backupCount)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    qt_handler = QtHandler(parent)
    qt_handler.setLevel(logging.INFO)
    logger.addHandler(qt_handler)

    return logger, qt_handler

class PortScannerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)

    def __init__(self, ip, start_port, end_port, thread_multiplier, timeout):
        super().__init__()
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.thread_multiplier = thread_multiplier
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
        self.output_lock = threading.Lock()
        self.stop_flag = threading.Event()

    def stop(self):
        self.stop_flag.set()

    def run(self):
        self.total_ports = self.end_port - self.start_port + 1
        self.scanned_ports = 0

        ports_per_thread = max(1, int(10 / self.thread_multiplier))
        num_threads = min(self.total_ports, max(1, int(self.total_ports / ports_per_thread)))

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            port_ranges = [range(i, min(i + ports_per_thread, self.end_port + 1))
                           for i in range(self.start_port, self.end_port + 1, ports_per_thread)]

            futures = [executor.submit(self.scan_ports, port_range) for port_range in port_ranges]
            for future in as_completed(futures):
                if self.stop_flag.is_set():
                    break
            executor.shutdown(wait=False)

        self.progress_signal.emit(100)
        if self.stop_flag.is_set():
            self.update_signal.emit("扫描已停止")
        else:
            self.update_signal.emit(f"扫描完成。找到 {len(self.open_ports)} 个开放端口。")

    def scan_ports(self, ports):
        local_open_ports = []
        for port in ports:
            if self.stop_flag.is_set():
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((self.ip, port))
                    if result == 0:
                        local_open_ports.append(port)
            except:
                pass
            finally:
                with self.lock:
                    self.scanned_ports += 1
                    progress = min(99, int((self.scanned_ports / self.total_ports) * 100))
                    self.progress_signal.emit(progress)

        with self.output_lock:
            for port in local_open_ports:
                self.open_ports.append(port)
                self.update_signal.emit(f"端口 {port} 开放")


class IPToolsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self.create_ip_info_tab(), "IP信息")
        self.tab_widget.addTab(self.create_port_status_tab(), "端口状态")
        self.tab_widget.addTab(self.create_url_status_tab(), "URL状态码")
        self.tab_widget.addTab(self.create_port_scanner_tab(), "本地端口扫描")

        layout.addWidget(self.tab_widget)
        self.setLayout(layout)

    def create_ip_info_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        input_layout = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("输入IP地址")
        input_layout.addWidget(self.ip_input)

        check_button = QPushButton("查询")
        check_button.clicked.connect(self.check_ip_info)
        input_layout.addWidget(check_button)

        layout.addLayout(input_layout)

        self.ip_result = QTextEdit()
        self.ip_result.setReadOnly(True)
        layout.addWidget(self.ip_result)

        return widget

    def create_port_status_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        input_layout = QHBoxLayout()
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("输入IP地址或域名")
        input_layout.addWidget(self.host_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("输入端口")
        input_layout.addWidget(self.port_input)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP"])
        input_layout.addWidget(self.protocol_combo)

        check_button = QPushButton("查询")
        check_button.clicked.connect(self.check_port_status)
        input_layout.addWidget(check_button)

        layout.addLayout(input_layout)

        self.port_result = QTextEdit()
        self.port_result.setReadOnly(True)
        layout.addWidget(self.port_result)

        return widget

    def create_url_status_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        input_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("输入URL")
        input_layout.addWidget(self.url_input)

        check_button = QPushButton("查询")
        check_button.clicked.connect(self.check_url_status)
        input_layout.addWidget(check_button)

        layout.addLayout(input_layout)

        self.url_result = QTextEdit()
        self.url_result.setReadOnly(True)
        layout.addWidget(self.url_result)

        return widget

    def create_port_scanner_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        input_layout = QHBoxLayout()
        self.scanner_ip_input = QLineEdit()
        self.scanner_ip_input.setPlaceholderText("输入IP地址或主机名")
        input_layout.addWidget(self.scanner_ip_input)

        self.start_port_input = QLineEdit()
        self.start_port_input.setPlaceholderText("起始端口")
        input_layout.addWidget(self.start_port_input)

        self.end_port_input = QLineEdit()
        self.end_port_input.setPlaceholderText("结束端口")
        input_layout.addWidget(self.end_port_input)

        self.thread_multiplier_combo = QComboBox()
        self.thread_multiplier_combo.addItems([f"{i}x" for i in range(1, 11)])
        input_layout.addWidget(self.thread_multiplier_combo)

        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText("延时(秒)")
        input_layout.addWidget(self.timeout_input)

        self.scan_button = QPushButton("扫描")
        self.scan_button.clicked.connect(self.start_port_scan)
        input_layout.addWidget(self.scan_button)

        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self.stop_port_scan)
        self.stop_button.setEnabled(False)
        input_layout.addWidget(self.stop_button)

        layout.addLayout(input_layout)

        self.scan_progress = QProgressBar()
        layout.addWidget(self.scan_progress)

        self.scan_result = QTextEdit()
        self.scan_result.setReadOnly(True)
        layout.addWidget(self.scan_result)

        return widget

    def check_ip_info(self):
        ip = self.ip_input.text().strip()
        if not self.is_valid_ipv4(ip):
            resolved_ip = self.resolve_to_ipv4(ip)
            if not resolved_ip:
                self.ip_result.setPlainText("无效的IP地址或无法解析的主机名")
                return
            ip = resolved_ip

        url = f"https://uapis.cn/api/ipinfo?ip={ip}"
        self.make_request(url, self.ip_result)

    def check_port_status(self):
        host = self.host_input.text().strip()
        port = self.port_input.text().strip()
        protocol = self.protocol_combo.currentText().lower()

        host = re.sub(r'^https?://', '', host)

        if ':' in host:
            host, port = host.split(':', 1)

        if not port.isdigit():
            self.port_result.setPlainText("请输入有效的端口号")
            return

        url = f"https://uapis.cn/api/portstats?host={host}&port={port}&protocol={protocol}"
        self.make_request(url, self.port_result)

    def check_url_status(self):
        url = self.url_input.text().strip()
        url = re.sub(r'^https?://', '', url)
        url = re.sub(r':\d+', '', url)
        api_url = f"https://uapis.cn/api/urlstatuscode?url=http://{url}"
        self.make_request(api_url, self.url_result)

    def start_port_scan(self):
        ip = self.scanner_ip_input.text().strip()
        start_port = int(self.start_port_input.text() or 1)
        end_port = int(self.end_port_input.text() or 65535)
        thread_multiplier = int(self.thread_multiplier_combo.currentText()[:-1])
        timeout = float(self.timeout_input.text() or 0.1)

        if not self.is_valid_ipv4(ip):
            resolved_ip = self.resolve_to_ipv4(ip)
            if not resolved_ip:
                self.scan_result.setPlainText("无效的IP地址或无法解析的主机名")
                return
            ip = resolved_ip

        self.scan_result.clear()
        self.scan_progress.setValue(0)

        self.scanner_thread = PortScannerThread(ip, start_port, end_port, thread_multiplier, timeout)
        self.scanner_thread.update_signal.connect(self.update_scan_result)
        self.scanner_thread.progress_signal.connect(self.scan_progress.setValue)
        self.scanner_thread.finished.connect(self.on_scan_finished)
        self.scanner_thread.start()

        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_port_scan(self):
        if hasattr(self, 'scanner_thread') and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scan_result.append("正在停止扫描...")
            self.stop_button.setEnabled(False)

    def on_scan_finished(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_scan_result(self, message):
        self.scan_result.append(message)

    def is_valid_ipv4(self, ip):
        pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        return bool(pattern.match(ip))

    def resolve_to_ipv4(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def make_request(self, url, result_widget):
        try:
            response = requests.get(url)
            data = response.json()
            if data['code'] == 200:
                result = "\n".join([f"{k}: {v}" for k, v in data.items() if k != 'code'])
                result_widget.setPlainText(result)
            else:
                result_widget.setPlainText(f"查询失败: {data.get('msg', '未知错误')}")
        except Exception as e:
            result_widget.setPlainText(f"查询错误: {str(e)}")

    def update_style(self, is_dark):
        style = """
		QWidget {
			background-color: #2D2D2D;
			color: #FFFFFF;
		}
		QLineEdit, QTextEdit, QComboBox {
			background-color: #3D3D3D;
			border: 1px solid #555555;
			color: #FFFFFF;
			padding: 5px;
		}
		QPushButton {
			background-color: #0D47A1;
			color: white;
			border: none;
			padding: 5px 10px;
		}
		QPushButton:hover {
			background-color: #1565C0;
		}
		QPushButton:pressed {
			background-color: #0D47A1;
		}
		QPushButton:disabled {
			background-color: #CCCCCC;
			color: #666666;
		}
		QTabWidget::pane {
			border: 1px solid #555555;
		}
		QTabBar::tab {
			background-color: #2D2D2D;
			color: #FFFFFF;
			padding: 5px;
		}
		QTabBar::tab:selected {
			background-color: #3D3D3D;
		}
		""" if is_dark else """
		QWidget {
			background-color: #FFFFFF;
			color: #000000;
		}
		QLineEdit, QTextEdit, QComboBox {
			background-color: #F0F0F0;
			border: 1px solid #CCCCCC;
			color: #000000;
			padding: 5px;
		}
		QPushButton {
			background-color: #4CAF50;
			color: white;
			border: none;
			padding: 5px 10px;
		}
		QPushButton:hover {
			background-color: #45a049;
		}
		QPushButton:pressed {
			background-color: #4CAF50;
		}
		QPushButton:disabled {
			background-color: #CCCCCC;
			color: #666666;
		}
		QTabWidget::pane {
			border: 1px solid #CCCCCC;
		}
		QTabBar::tab {
			background-color: #F0F0F0;
			color: #000000;
			padding: 5px;
		}
		QTabBar::tab:selected {
			background-color: #FFFFFF;
		}
		"""
        self.setStyleSheet(style)

        for i in range(self.tab_widget.count()):
            tab = self.tab_widget.widget(i)
            tab.setStyleSheet(style)


class PingThread(QThread):
    update_signal = pyqtSignal(str, object)

    def __init__(self, target, ping_type):
        super().__init__()
        self.target = target
        self.ping_type = ping_type

    def run(self):
        if self.ping_type == "ICMP":
            result = self.icmp_ping()
        elif self.ping_type == "TCP":
            result = self.tcp_ping()
        elif self.ping_type == "HTTP":
            result = self.http_ping()
        elif self.ping_type == "HTTPS":
            result = self.https_ping()
        elif self.ping_type == "JavaMC":
            result = self.java_mc_ping()
        elif self.ping_type == "BedrockMC":
            result = self.bedrock_mc_ping()
        else:
            result = None

        if result is not None:
            self.update_signal.emit(self.target, result)

    def icmp_ping(self):
        try:
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                output = subprocess.check_output(
                    ["ping", "-n", "4", self.target],
                    universal_newlines=True,
                    stderr=subprocess.STDOUT,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                output = subprocess.check_output(
                    ["ping", "-c", "4", self.target],
                    universal_newlines=True,
                    stderr=subprocess.STDOUT
                )

            # 提取延迟时间，包括 <1ms 的情况
            times = re.findall(r"时间[=<](\d+|<1)ms", output)

            # 处理延迟时间
            processed_times = []
            for t in times:
                if t == '<1':
                    processed_times.append(0.5)  # 将 <1ms 视为 0.5ms
                else:
                    processed_times.append(float(t))

            if processed_times:
                return {
                    'min': min(processed_times),
                    'max': max(processed_times),
                    'avg': sum(processed_times) / len(processed_times),
                    'loss': self.calculate_packet_loss(output)
                }
            else:
                return "Ping 成功，但无法提取延迟信息"
        except subprocess.CalledProcessError as e:
            error_output = e.output.strip()
            if "无法访问目标主机" in error_output:
                return "无法访问目标主机"
            elif "请求超时" in error_output:
                return "请求超时"
            elif "一般故障" in error_output:
                return "一般故障"
            else:
                return f"Ping 失败: {error_output}"
        except Exception as e:
            return f"Ping 错误: {str(e)}"

    def calculate_packet_loss(self, output):
        match = re.search(r"(\d+)% 丢失", output)
        if match:
            return int(match.group(1))
        return None

    def tcp_ping(self):
        port = 80  # 默认使用 80 端口
        if ':' in self.target:
            host, port = self.target.split(':')
            port = int(port)
        else:
            host = self.target

        results = []
        total_time = 0
        success = 0
        attempts = 4  # 进行 4 次尝试，与 ICMP ping 保持一致

        for _ in range(attempts):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 设置 1 秒超时
                start_time = time.time()
                result = sock.connect_ex((host, port))
                end_time = time.time()

                if result == 0:
                    latency = (end_time - start_time) * 1000  # 转换为毫秒
                    results.append(latency)
                    total_time += latency
                    success += 1
                    self.update_signal.emit(self.target, f"连接成功: {latency:.2f}ms")
                else:
                    self.update_signal.emit(self.target, f"连接失败: {socket.error(result)}")
            except socket.gaierror:
                self.update_signal.emit(self.target, "名称解析失败")
                return "名称解析失败"
            except socket.timeout:
                self.update_signal.emit(self.target, "连接超时")
            except Exception as e:
                self.update_signal.emit(self.target, f"错误: {str(e)}")
            finally:
                sock.close()

            time.sleep(1)  # 在每次尝试之间等待 1 秒

        if success > 0:
            avg_latency = total_time / success
            loss_rate = (attempts - success) / attempts * 100
            return {
                'min': min(results) if results else None,
                'max': max(results) if results else None,
                'avg': avg_latency,
                'loss': loss_rate
            }
        else:
            return "所有 TCP 连接尝试均失败"

    def http_ping(self):
        try:
            start_time = time.time()
            requests.get(f"http://{self.target}", timeout=5)
            return (time.time() - start_time) * 1000
        except requests.RequestException:
            return None

    def https_ping(self):
        try:
            start_time = time.time()
            requests.get(f"https://{self.target}", timeout=5, verify=False)
            return (time.time() - start_time) * 1000
        except requests.RequestException:
            return None

    def java_mc_ping(self):
        try:
            server = JavaServer.lookup(self.target)
            status = server.status()
            return {
                '延迟': status.latency,
                '版本': status.version.name,
                '协议': status.version.protocol,
                '在线玩家': status.players.online,
                '最大玩家': status.players.max,
                '描述': status.description
            }
        except Exception as e:
            return f"错误: {str(e)}"

    def bedrock_mc_ping(self):
        try:
            server = BedrockServer.lookup(self.target)
            status = server.status()
            return {
                '延迟': status.latency,
                '版本': status.version.name,
                '协议': status.version.protocol,
                '在线玩家': status.players.online,
                '最大玩家': status.players.max,
                '游戏模式': status.gamemode,
                '地图': status.map_name
            }
        except Exception as e:
            return f"错误: {str(e)}"


class NodeSelectionDialog(QDialog):
    """节点选择对话框"""

    def __init__(self, nodes, parent=None):
        super().__init__(parent)
        self.nodes = nodes
        self.selected_nodes = []
        self.initUI()

    def initUI(self):
        self.setWindowTitle("选择节点")
        layout = QVBoxLayout()

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.available_list = QListWidget()
        self.selected_list = QListWidget()

        for node in self.nodes:
            self.available_list.addItem(node['name'])

        splitter.addWidget(self.available_list)
        splitter.addWidget(self.selected_list)

        layout.addWidget(splitter)

        button_layout = QHBoxLayout()
        ok_button = QPushButton("确定")
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("取消")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.available_list.itemClicked.connect(self.add_node)
        self.selected_list.itemDoubleClicked.connect(self.remove_node)

    def add_node(self, item):
        self.available_list.takeItem(self.available_list.row(item))
        self.selected_list.addItem(item.text())

    def remove_node(self, item):
        self.selected_list.takeItem(self.selected_list.row(item))
        self.available_list.addItem(item.text())

    def accept(self):
        self.selected_nodes = [self.selected_list.item(i).text() for i in range(self.selected_list.count())]
        if not self.selected_nodes:
            QMessageBox.warning(self, "警告", "请至少选择一个节点")
        else:
            super().accept()


class WorkerThread(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, function, *args, **kwargs):
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs

    def run(self):
        while not self.isInterruptionRequested():
            result = self.function(*self.args, **self.kwargs)
            self.update_signal.emit(str(result))
            if self.isInterruptionRequested():
                break
            self.msleep(100)

class TunnelCard(QFrame):
    clicked = pyqtSignal(object, bool)
    start_stop_signal = pyqtSignal(object, bool)

    def __init__(self, tunnel_info, token):
        super().__init__()
        self.tunnel_info = tunnel_info
        self.token = token
        self.node_domain = None
        self.is_running = False
        self.is_selected = False
        self.initUI()
        self.updateStyle()
        self.fetch_node_info()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        name_label = QLabel(f"<b>{self.tunnel_info.get('name', 'Unknown')}</b>")
        name_label.setObjectName("nameLabel")
        type_label = QLabel(f"类型: {self.tunnel_info.get('type', 'Unknown')}")
        local_label = QLabel(
            f"本地: {self.tunnel_info.get('localip', 'Unknown')}:{self.tunnel_info.get('nport', 'Unknown')}")
        remote_label = QLabel(f"远程端口: {self.tunnel_info.get('dorp', 'Unknown')}")
        node_label = QLabel(f"节点: {self.tunnel_info.get('node', 'Unknown')}")

        self.status_label = QLabel("状态: 未启动")

        self.link_label = QLabel(f"连接: {self.get_link()}")
        self.link_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.link_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.link_label.mousePressEvent = self.copy_link

        self.start_stop_button = QPushButton("启动")
        self.start_stop_button.clicked.connect(self.toggle_start_stop)

        layout.addWidget(name_label)
        layout.addWidget(type_label)
        layout.addWidget(local_label)
        layout.addWidget(remote_label)
        layout.addWidget(node_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.link_label)
        layout.addWidget(self.start_stop_button)

        self.setLayout(layout)
        self.setFixedSize(250, 250)

    def fetch_node_info(self):
        node = self.tunnel_info.get('node', '')
        url = f"http://cf-v2.uapis.cn/nodeinfo"
        params = {
            'token': self.token,
            'node': node
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                self.node_domain = data['data']['ip']
                self.update_link_label()
        except Exception as e:
            print(f"Error fetching node info: {e}")

    def get_link(self):
        domain = self.node_domain or self.tunnel_info.get('node', '')
        port = self.tunnel_info.get('dorp', '')
        return f"{domain}:{port}"

    def update_link_label(self):
        if hasattr(self, 'link_label'):
            self.link_label.setText(f"连接: {self.get_link()}")

    def copy_link(self, event):
        link = self.get_link()
        pyperclip.copy(link)
        QToolTip.showText(event.globalPosition().toPoint(), "链接已复制!", self)

    def get_tunnel_domain(self):
        tunnel_type = self.tunnel_info.get('type', '').lower()
        if tunnel_type in ['http', 'https']:
            return self.tunnel_info.get('custom_domains', [''])[0]  # 获取第一个自定义域名
        else:
            return self.tunnel_info.get('node', '')  # 如果不是 HTTP/HTTPS，则使用节点名称

    def toggle_start_stop(self):
        self.is_running = not self.is_running
        self.update_status()
        self.start_stop_signal.emit(self.tunnel_info, self.is_running)

    def update_status(self):
        if self.is_running:
            self.status_label.setText("状态: 运行中")
            self.start_stop_button.setText("停止")
        else:
            self.status_label.setText("状态: 未启动")
            self.start_stop_button.setText("启动")
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self.is_running:
            color = QColor(0, 255, 0)  # 绿色
        else:
            color = QColor(255, 0, 0)  # 红色
        painter.setPen(QPen(color, 2))
        painter.setBrush(color)
        painter.drawEllipse(self.width() - 20, 10, 10, 10)

    def updateStyle(self):
        self.setStyleSheet("""
			TunnelCard {
				border: 1px solid #d0d0d0;
				border-radius: 5px;
				padding: 10px;
				margin: 5px;
			}
			TunnelCard:hover {
				background-color: rgba(240, 240, 240, 50);
			}
			#nameLabel {
				font-size: 16px;
				font-weight: bold;
			}
		""")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.is_selected = not self.is_selected
            self.setSelected(self.is_selected)
            self.clicked.emit(self.tunnel_info, self.is_selected)
        super().mousePressEvent(event)

    def setSelected(self, selected):
        self.is_selected = selected
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "TunnelCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "TunnelCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))


class BatchEditDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("批量编辑隧道")
        self.layout = QVBoxLayout(self)

        self.node_combo = QComboBox()
        self.node_combo.addItem("不修改")
        self.node_combo.addItems([node['name'] for node in get_nodes()])

        self.type_combo = QComboBox()
        self.type_combo.addItem("不修改")
        self.type_combo.addItems(["tcp", "udp", "http", "https"])

        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("不修改")

        self.local_port_input = QLineEdit()
        self.local_port_input.setPlaceholderText("不修改")

        self.remote_port_input = QLineEdit()
        self.remote_port_input.setPlaceholderText("不修改")

        form_layout = QFormLayout()
        form_layout.addRow("节点:", self.node_combo)
        form_layout.addRow("类型:", self.type_combo)
        form_layout.addRow("本地IP/主机名:", self.local_ip_input)
        form_layout.addRow("本地端口:", self.local_port_input)
        form_layout.addRow("远程端口:", self.remote_port_input)

        self.layout.addLayout(form_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.layout.addWidget(buttons)

    def get_changes(self):
        changes = {}
        if self.node_combo.currentIndex() != 0:
            changes['node'] = self.node_combo.currentText()
        if self.type_combo.currentIndex() != 0:
            changes['type'] = self.type_combo.currentText()
        if self.local_ip_input.text():
            changes['localip'] = self.local_ip_input.text()
        if self.local_port_input.text():
            changes['nport'] = self.local_port_input.text()
        if self.remote_port_input.text():
            changes['dorp'] = self.remote_port_input.text()
        return changes


class DomainCard(QFrame):
    clicked = pyqtSignal(object)

    def __init__(self, domain_info):
        super().__init__()
        self.domain_info = domain_info
        self.initUI()
        self.updateStyle()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        domain_label = QLabel(f"<b>{self.domain_info['record']}.{self.domain_info['domain']}</b>")
        domain_label.setObjectName("nameLabel")
        type_label = QLabel(f"类型: {self.domain_info['type']}")
        target_label = QLabel(f"目标: {self.domain_info['target']}")
        ttl_label = QLabel(f"TTL: {self.domain_info['ttl']}")
        remarks_label = QLabel(f"备注: {self.domain_info.get('remarks', '无')}")

        self.link_label = QLabel(f"链接: {self.get_link()}")
        self.link_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.link_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.link_label.mousePressEvent = self.copy_link

        layout.addWidget(domain_label)
        layout.addWidget(type_label)
        layout.addWidget(target_label)
        layout.addWidget(ttl_label)
        layout.addWidget(remarks_label)
        layout.addWidget(self.link_label)

        self.setLayout(layout)
        self.setFixedSize(250, 200)

    def get_link(self):
        return f"{self.domain_info['record']}.{self.domain_info['domain']}"

    def copy_link(self, event):
        link = self.get_link()
        pyperclip.copy(link)
        QToolTip.showText(event.globalPosition().toPoint(), "链接已复制!", self)

    def updateStyle(self):
        self.setStyleSheet("""
			DomainCard {
				border: 1px solid #d0d0d0;
				border-radius: 5px;
				padding: 10px;
				margin: 5px;
			}
			DomainCard:hover {
				background-color: rgba(240, 240, 240, 50);
			}
			#nameLabel {
				font-size: 16px;
				font-weight: bold;
			}
		""")

    def setSelected(self, selected):
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "DomainCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "DomainCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.domain_info)
        super().mousePressEvent(event)


class ConfigEditorDialog(QDialog):
    def __init__(self, config_file_path, dark_theme, parent=None):
        super().__init__(parent)
        self.config_file_path = config_file_path
        self.dark_theme = dark_theme
        self.initUI()
        self.apply_theme()

    def initUI(self):
        self.setWindowTitle("编辑配置文件")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout(self)

        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        self.text_edit = QTextEdit()
        self.tab_widget.addTab(self.text_edit, "文本编辑")

        visual_edit_widget = QWidget()
        visual_edit_layout = QFormLayout(visual_edit_widget)
        self.tab_widget.addTab(visual_edit_widget, "可视化编辑")

        self.token_input = QLineEdit()
        self.nodes_input = QLineEdit()
        self.tunnel_name_input = QLineEdit()
        self.domain_input = QLineEdit()
        self.subdomain_input = QLineEdit()
        self.record_type_combo = QComboBox()
        self.record_type_combo.addItems(["A", "SRV"])

        visual_edit_layout.addRow("Token:", self.token_input)
        visual_edit_layout.addRow("节点 (逗号分隔):", self.nodes_input)
        visual_edit_layout.addRow("隧道名称:", self.tunnel_name_input)
        visual_edit_layout.addRow("域名:", self.domain_input)
        visual_edit_layout.addRow("子域名:", self.subdomain_input)
        visual_edit_layout.addRow("记录类型:", self.record_type_combo)

        self.srv_widget = QWidget()
        srv_layout = QFormLayout(self.srv_widget)
        self.priority_input = QLineEdit("10")
        self.weight_input = QLineEdit("10")
        self.port_input = QLineEdit()
        srv_layout.addRow("优先级:", self.priority_input)
        srv_layout.addRow("权重:", self.weight_input)
        srv_layout.addRow("端口:", self.port_input)
        visual_edit_layout.addRow(self.srv_widget)

        self.record_type_combo.currentTextChanged.connect(self.on_record_type_changed)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.load_config()

    def apply_theme(self):
        if self.dark_theme:
            self.setStyleSheet("""
				QDialog, QTabWidget, QTextEdit, QLineEdit, QComboBox {
					background-color: #2D2D2D;
					color: #FFFFFF;
				}
				QTabWidget::pane {
					border: 1px solid #555555;
				}
				QTabBar::tab {
					background-color: #3D3D3D;
					color: #FFFFFF;
					padding: 5px;
				}
				QTabBar::tab:selected {
					background-color: #4D4D4D;
				}
				QPushButton {
					background-color: #0D47A1;
					color: white;
					border: none;
					padding: 5px 10px;
					text-align: center;
					text-decoration: none;
					font-size: 14px;
					margin: 4px 2px;
					border-radius: 4px;
				}
				QPushButton:hover {
					background-color: #1565C0;
				}
				QLabel {
					color: #FFFFFF;
				}
			""")
        else:
            self.setStyleSheet("")  # 使用默认浅色主题

    def on_record_type_changed(self):
        self.srv_widget.setVisible(self.record_type_combo.currentText() == "SRV")

    def load_config(self):
        with open(self.config_file_path, 'r') as f:
            config_content = f.read()
        self.text_edit.setPlainText(config_content)

        try:
            config = ast.literal_eval(config_content)
            if isinstance(config, list) and len(config) >= 6:
                self.token_input.setText(config[0])
                self.nodes_input.setText(", ".join(config[2:2 + int(config[1])]))
                self.tunnel_name_input.setText(config[2 + int(config[1])])
                self.domain_input.setText(config[3 + int(config[1])])
                self.subdomain_input.setText(config[4 + int(config[1])])
                self.record_type_combo.setCurrentText(config[5 + int(config[1])])
                if len(config) > 6 + int(config[1]) and config[5 + int(config[1])] == "SRV":
                    self.priority_input.setText(config[6 + int(config[1])])
                    self.weight_input.setText(config[7 + int(config[1])])
                    self.port_input.setText(config[8 + int(config[1])])
        except:
            pass

    def get_config(self):
        if self.tab_widget.currentIndex() == 0:
            return self.text_edit.toPlainText()
        else:
            # 可视化编辑模式
            nodes = [node.strip() for node in self.nodes_input.text().split(',')]
            config = [
                self.token_input.text(),
                len(nodes),
                *nodes,
                self.tunnel_name_input.text(),
                self.domain_input.text(),
                self.subdomain_input.text(),
                self.record_type_combo.currentText()
            ]
            if self.record_type_combo.currentText() == "SRV":
                config.extend([
                    self.priority_input.text(),
                    self.weight_input.text(),
                    self.port_input.text()
                ])
            return str(config)

class StopWorker(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(str)

    def __init__(self, running_tunnels, tunnel_processes, logger):
        super().__init__()
        self.running_tunnels = running_tunnels
        self.tunnel_processes = tunnel_processes
        self.logger = logger

    def run(self):
        self.progress.emit("开始停止所有隧道...")

        # 停止普通隧道
        for tunnel_name in list(self.tunnel_processes.keys()):
            self.stop_single_tunnel(tunnel_name, is_dynamic=False)

        # 确保所有 frpc.exe 进程都被终止
        self.kill_remaining_frpc_processes()

        self.progress.emit("所有隧道已停止")
        self.finished.emit()

    def stop_single_tunnel(self, tunnel_name, is_dynamic):
        self.progress.emit(f"正在停止隧道: {tunnel_name}")
        if is_dynamic:
            worker = self.running_tunnels.get(tunnel_name)
            if worker:
                worker.requestInterruption()
                if not worker.wait(5000):  # 等待最多5秒
                    worker.terminate()
                    worker.wait(2000)
                del self.running_tunnels[tunnel_name]
        else:
            process = self.tunnel_processes.get(tunnel_name)
            if process:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                del self.tunnel_processes[tunnel_name]

        self.logger.info(f"隧道 '{tunnel_name}' 已停止")

    def kill_remaining_frpc_processes(self):
        self.progress.emit("正在清理残留的 frpc.exe 进程...")
        killed_count = 0

        try:
            # 获取当前目录下的 frpc.exe 完整路径
            frpc_path = get_absolute_path('frpc.exe').replace('\\', '\\\\')  # 转义反斜杠

            ps_command = (
                f'powershell -Command "Get-Process | Where-Object {{ $_.Path -eq \'{frpc_path}\' }} | '
                'Stop-Process -Force"'
            )
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

            subprocess.Popen(ps_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             startupinfo=startupinfo)
            killed_count += 1
            self.logger.info("已通过 PowerShell 强制终止 frpc.exe 进程")
        except Exception as e:
            self.logger.error(f"使用 PowerShell 终止 frpc.exe 时发生错误: {str(e)}")

        if killed_count > 0:
            self.progress.emit(f"已终止 {killed_count} 个残留的 frpc.exe 进程")
        else:
            self.progress.emit("没有发现残留的 frpc.exe 进程")


class OutputDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("隧道输出")
        self.setGeometry(100, 100, 800, 600)
        self.layout = QVBoxLayout(self)

        self.output_text_edit = QTextEdit()
        self.output_text_edit.setReadOnly(True)
        self.layout.addWidget(self.output_text_edit)

        # 存储每个隧道的输出历史记录
        self.tunnel_outputs = {}

    def add_output(self, tunnel_name, output, run_number):
        """
        添加或更新隧道输出

        Args:
            tunnel_name: 隧道名称
            output: 输出内容
            run_number: 运行次数
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        separator = f'<hr><b>隧道: {tunnel_name}</b> (启动次数: {run_number}) - <i>{timestamp}</i><br>'

        if tunnel_name in self.tunnel_outputs:
            current_text = self.output_text_edit.toHtml()
            if self.tunnel_outputs[tunnel_name]['run_number'] == run_number:
                # 如果是相同的运行次数，替换对应的输出部分
                start_idx = current_text.find(f'<b>隧道: {tunnel_name}</b> (启动次数: {run_number})')
                if start_idx != -1:
                    # 查找下一个分隔符或文档末尾
                    end_idx = current_text.find('<hr>', start_idx + 1)
                    if end_idx == -1:
                        end_idx = len(current_text)
                    # 替换这部分内容
                    new_text = current_text[:start_idx] + separator + output + current_text[end_idx:]
                    self.output_text_edit.setHtml(new_text)
                else:
                    # 如果找不到对应的输出块（不应该发生），添加到末尾
                    self.output_text_edit.append(separator + output)
            else:
                # 如果是新的运行次数，在开头添加新的输出
                self.output_text_edit.setHtml(separator + output + current_text)
        else:
            # 第一次添加该隧道的输出
            self.output_text_edit.append(separator + output)

        # 更新存储的输出信息
        self.tunnel_outputs[tunnel_name] = {
            'output': output,
            'run_number': run_number
        }

        # 滚动到顶部 以显示最新的输出
        self.output_text_edit.verticalScrollBar().setValue(0)


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("设置")
        self.setFixedWidth(400)
        self.init_ui()
        self.load_settings()
        self.apply_theme(parent.dark_theme)

    def init_ui(self):
        layout = QVBoxLayout(self)

        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        # === 常规标签页 ===
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)

        # 自启动选项
        self.autostart_checkbox = QCheckBox("开机自启动")
        self.autostart_checkbox.stateChanged.connect(self.toggle_autostart)
        general_layout.addWidget(self.autostart_checkbox)

        # 主题设置
        theme_group = QGroupBox("主题设置")
        theme_layout = QVBoxLayout()
        self.theme_light = QRadioButton("浅色")
        self.theme_dark = QRadioButton("深色")
        self.theme_system = QRadioButton("跟随系统")
        theme_layout.addWidget(self.theme_light)
        theme_layout.addWidget(self.theme_dark)
        theme_layout.addWidget(self.theme_system)
        theme_group.setLayout(theme_layout)
        general_layout.addWidget(theme_group)

        # 日志设置组
        log_group = QGroupBox("日志设置")
        log_layout = QFormLayout()

        # 日志文件大小设置
        self.log_size_input = QLineEdit()
        self.log_size_input.setValidator(QIntValidator(1, 1000))  # 限制输入为1-1000
        self.log_size_input.setPlaceholderText("1-1000")
        size_layout = QHBoxLayout()
        size_layout.addWidget(self.log_size_input)
        size_layout.addWidget(QLabel("MB"))
        log_layout.addRow("日志文件大小:", size_layout)

        # 日志文件备份数量设置
        self.backup_count_input = QLineEdit()
        self.backup_count_input.setValidator(QIntValidator(1, 100))  # 限制输入为1-100
        self.backup_count_input.setPlaceholderText("1-100")
        log_layout.addRow("日志文件备份数量:", self.backup_count_input)

        # 添加日志设置说明
        log_note = QLabel("注: 更改将在重启程序后生效")
        log_note.setStyleSheet("color: gray; font-size: 10px;")
        log_layout.addRow("", log_note)

        log_group.setLayout(log_layout)
        general_layout.addWidget(log_group)

        general_layout.addStretch()
        tab_widget.addTab(general_tab, "常规")

        # === 隧道标签页 ===
        tunnel_tab = QWidget()
        tunnel_layout = QVBoxLayout(tunnel_tab)

        tunnel_layout.addWidget(QLabel("程序启动时自动启动以下隧道:"))
        self.tunnel_list = QListWidget()
        tunnel_layout.addWidget(self.tunnel_list)

        # 添加隧道设置说明
        tunnel_note = QLabel("注: 勾选的隧道将在程序启动时自动启动")
        tunnel_note.setStyleSheet("color: gray; font-size: 10px;")
        tunnel_layout.addWidget(tunnel_note)

        tab_widget.addTab(tunnel_tab, "隧道")

        # === 关于标签页 ===
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        about_layout.setSpacing(15)

        # Logo图片
        logo_label = QLabel()
        logo_pixmap = QPixmap("/api/placeholder/100/100")  # 100x100 的占位图
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setStyleSheet("margin-top: 20px;")
        about_layout.addWidget(logo_label)

        # 标题
        title_label = QLabel(APP_NAME)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px 0px;")
        about_layout.addWidget(title_label)

        # 版本信息
        version_label = QLabel(f"Version {APP_VERSION}")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_label.setStyleSheet("font-size: 14px; color: #666666;")
        about_layout.addWidget(version_label)

        # 描述文本
        desc_text = QTextBrowser()  # 使用QTextBrowser代替QTextEdit以支持链接点击
        desc_text.setOpenLinks(True)  # 允许打开链接
        desc_text.setOpenExternalLinks(True)  # 在外部浏览器中打开链接
        desc_text.setStyleSheet("""
                    QTextBrowser {
                        border: 1px solid #cccccc;
                        border-radius: 5px;
                        padding: 10px;
                        background-color: transparent;
                    }
                    QTextBrowser:hover {
                        border-color: #999999;
                    }
                """)

        desc_text.setHtml(f"""
                    <div style="text-align: center; margin-bottom: 20px;">
                        <p style="font-size: 14px; line-height: 1.6;">
                            基于chmlfrp api开发的chmlfrp ui版本的客户端<br>
                            如有bug请提出谢谢!
                        </p>
                        <p style="color: #666666;">
                            有bug请投稿至 <a href="mailto:boring_student@qq.com" style="color: #0066cc;">boring_student@qq.com</a>
                        </p>
                    </div>

                    <div style="margin: 20px 0;">
                        <h3 style="color: #333333; border-bottom: 1px solid #eeeeee; padding-bottom: 8px;">相关链接</h3>
                        <ul style="list-style-type: none; padding-left: 0;">
                            <li style="margin: 8px 0;"><a href="https://github.com/Qianyiaz/ChmlFrp_Professional_Launcher" style="color: #0066cc; text-decoration: none;">▸ 千依🅥的cpl</a></li>
                            <li style="margin: 8px 0;"><a href="https://github.com/FengXiang2233/Xingcheng-Chmlfrp-Lanucher" style="color: #0066cc; text-decoration: none;">▸ 枫相的xcl2</a></li>
                            <li style="margin: 8px 0;"><a href="https://github.com/boringstudents/CHMLFRP_UI" style="color: #0066cc; text-decoration: none;">▸ 我的"不道a"</a></li>
                            <li style="margin: 8px 0;"><a href="https://github.com/TechCat-Team/ChmlFrp-Frp" style="color: #0066cc; text-decoration: none;">▸ chmlfrp官方魔改的frpc</a></li>
                        </ul>
                    </div>

                    <div style="margin: 20px 0;">
                        <h3 style="color: #333333; border-bottom: 1px solid #eeeeee; padding-bottom: 8px;">API文档</h3>
                        <ul style="list-style-type: none; padding-left: 0;">
                            <li style="margin: 8px 0;"><a href="https://docs.northwind.top/#/" style="color: #0066cc; text-decoration: none;">▸ 群友的api文档</a></li>
                            <li style="margin: 8px 0;"><a href="https://apifox.com/apidoc/shared-24b31bd1-e48b-44ab-a486-81cf5f964422/" style="color: #0066cc; text-decoration: none;">▸ 官方api v2文档</a></li>
                        </ul>
                    </div>

                    <div style="text-align: center; margin-top: 20px;">
                        <p style="margin: 8px 0;"><a href="http://chmlfrp.cn" style="color: #0066cc; text-decoration: none;">官网：chmlfrp.cn</a></p>
                        <p style="margin: 8px 0;"><a href="http://panel.chmlfrp.cn" style="color: #0066cc; text-decoration: none;">v2控制面板：panel.chmlfrp.cn</a></p>
                        <p style="margin: 8px 0;"><a href="http://preview.panel.chmlfrp.cn" style="color: #0066cc; text-decoration: none;">v3控制面板：preview.panel.chmlfrp.cn</a></p>
                    </div>
                """)
        desc_text.setMinimumHeight(300)
        about_layout.addWidget(desc_text)

        about_layout.addStretch()
        tab_widget.addTab(about_tab, "关于")

        # === 底部按钮 ===
        button_layout = QHBoxLayout()
        save_button = QPushButton("保存")
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton("取消")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

    def apply_theme(self, is_dark):
        if is_dark:
            style = """
                QDialog, QTabWidget, QWidget {
                    background-color: #2D2D2D;
                    color: #FFFFFF;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                }
                QTabBar::tab {
                    background-color: #3D3D3D;
                    color: #FFFFFF;
                    padding: 5px;
                }
                QTabBar::tab:selected {
                    background-color: #4D4D4D;
                }
                QTextEdit {
                    background-color: #2D2D2D;
                    color: #FFFFFF;
                }
                QTextEdit a {
                    color: #00A0FF;
                }
                """ + self.get_base_dark_style()
        else:
            style = """
                QDialog, QTabWidget, QWidget {
                    background-color: #FFFFFF;
                    color: #000000;
                }
                QTabWidget::pane {
                    border: 1px solid #CCCCCC;
                }
                QTabBar::tab {
                    background-color: #F0F0F0;
                    color: #000000;
                    padding: 5px;
                }
                QTabBar::tab:selected {
                    background-color: #FFFFFF;
                }
                QTextEdit {
                    background-color: #FFFFFF;
                    color: #000000;
                }
                QTextEdit a {
                    color: #0066CC;
                }
                """ + self.get_base_light_style()

        self.setStyleSheet(style)

    def get_base_dark_style(self):
        return """
            QGroupBox {
                border: 1px solid #555555;
                margin-top: 1em;
                padding-top: 0.5em;
            }
            QCheckBox, QRadioButton {
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #0D47A1;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
            QListWidget {
                background-color: #3D3D3D;
                border: 1px solid #555555;
            }
        """

    def get_base_light_style(self):
        return """
            QGroupBox {
                border: 1px solid #CCCCCC;
                margin-top: 1em;
                padding-top: 0.5em;
            }
            QCheckBox, QRadioButton {
                color: #000000;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QListWidget {
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
            }
        """

    def load_settings(self):
        # 读取配置文件
        settings_path = get_absolute_path("settings.json")
        try:
            with open(settings_path, 'r') as f:
                settings = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            settings = {}
            self.parent.logger.info("未找到配置文件或配置文件无效，将使用默认设置")

        # 读取自启动状态
        if sys.platform == "win32":
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_READ
                )
                try:
                    winreg.QueryValueEx(key, "ChmlFrpUI")
                    self.autostart_checkbox.setChecked(True)
                except WindowsError:
                    self.autostart_checkbox.setChecked(False)
                winreg.CloseKey(key)
            except WindowsError as e:
                self.parent.logger.error(f"读取自启动设置失败: {str(e)}")
                self.autostart_checkbox.setChecked(False)

        # 加载日志设置
        try:
            log_size = settings.get('log_size_mb')
            if log_size is not None:
                self.log_size_input.setText(str(log_size))
            else:
                self.log_size_input.setText("10")

            backup_count = settings.get('backup_count')
            if backup_count is not None:
                self.backup_count_input.setText(str(backup_count))
            else:
                self.backup_count_input.setText("30")
        except Exception as e:
            self.parent.logger.error(f"加载日志设置失败: {str(e)}")
            self.log_size_input.setText("10")
            self.backup_count_input.setText("30")

        # 加载主题设置
        try:
            theme_setting = settings.get('theme', 'system')
            if theme_setting == 'light':
                self.theme_light.setChecked(True)
            elif theme_setting == 'dark':
                self.theme_dark.setChecked(True)
            else:
                self.theme_system.setChecked(True)
        except Exception as e:
            self.parent.logger.error(f"加载主题设置失败: {str(e)}")
            self.theme_system.setChecked(True)

        # 加载隧道设置
        try:
            # 清除现有项目
            self.tunnel_list.clear()

            # 获取自动启动的隧道列表
            auto_start_tunnels = settings.get('auto_start_tunnels', [])

            if self.parent.token:
                # 获取用户的隧道列表
                tunnels = get_user_tunnels(self.parent.token)
                if tunnels:
                    for tunnel in tunnels:
                        item = QListWidgetItem(tunnel['name'])
                        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                        # 设置选中状态
                        item.setCheckState(
                            Qt.CheckState.Checked if tunnel['name'] in auto_start_tunnels
                            else Qt.CheckState.Unchecked
                        )
                        self.tunnel_list.addItem(item)
                else:
                    no_tunnels_item = QListWidgetItem("无可用隧道")
                    self.tunnel_list.addItem(no_tunnels_item)
            else:
                not_logged_in_item = QListWidgetItem("请先登录")
                self.tunnel_list.addItem(not_logged_in_item)
        except Exception as e:
            self.parent.logger.error(f"加载隧道设置失败: {str(e)}")
            error_item = QListWidgetItem("加载隧道列表失败")
            self.tunnel_list.addItem(error_item)


    def toggle_autostart(self, state):
        if sys.platform == "win32":
            try:
                # 获取程序的完整路径
                if getattr(sys, 'frozen', False):
                    # 如果是打包后的 exe
                    program_path = f'"{sys.executable}"'
                else:
                    # 如果是 Python 脚本
                    program_path = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0,
                    winreg.KEY_ALL_ACCESS
                )

                if state == Qt.CheckState.Checked.value:
                    winreg.SetValueEx(key, "ChmlFrpUI", 0, winreg.REG_SZ, program_path)
                else:
                    try:
                        winreg.DeleteValue(key, "ChmlFrpUI")
                        self.parent.logger.info("已删除自启动项")
                    except WindowsError:
                        pass
                winreg.CloseKey(key)
            except Exception as e:
                self.parent.logger.error(f"设置自启动失败: {str(e)}")
                QMessageBox.warning(self, "错误", f"设置自启动失败: {str(e)}")

    def get_selected_theme(self):
        if self.theme_light.isChecked():
            return 'light'
        elif self.theme_dark.isChecked():
            return 'dark'
        else:
            return 'system'

    def save_settings(self):
        try:
            # 获取设置值
            log_size = int(self.log_size_input.text() or 10)
            backup_count = int(self.backup_count_input.text() or 30)

            # 保存自动启动的隧道列表
            auto_start_tunnels = []
            for i in range(self.tunnel_list.count()):
                item = self.tunnel_list.item(i)
                if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                    if item.checkState() == Qt.CheckState.Checked:
                        auto_start_tunnels.append(item.text())

            settings_path = get_absolute_path("settings.json")
            settings = {
                'auto_start_tunnels': auto_start_tunnels,
                'theme': self.get_selected_theme(),
                'log_size_mb': log_size,
                'backup_count': backup_count
            }

            with open(settings_path, 'w') as f:
                json.dump(settings, f)

            # 更新全局变量
            global maxBytes, backupCount
            maxBytes = log_size * 1024 * 1024
            backupCount = backup_count

            # 应用主题设置
            if self.get_selected_theme() == 'system':
                self.parent.dark_theme = self.parent.is_system_dark_theme()
            else:
                self.parent.dark_theme = (self.get_selected_theme() == 'dark')
            self.parent.apply_theme()

            QMessageBox.information(self, "成功", "设置已保存")
            self.accept()

        except Exception as e:
            QMessageBox.warning(self, "错误", f"保存设置失败: {str(e)}")


class MainWindow(QMainWindow):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.tab_buttons = []
        self.selected_tunnels = []
        self.token = None

        # 初始化输出互斥锁
        self.output_mutex = QMutex()

        # 初始化日志系统
        self.logger = logging.getLogger('CHMLFRP_UI')
        self.qt_handler = QtHandler(self)
        self.logger.addHandler(self.qt_handler)
        self.qt_handler.new_record.connect(self.update_log)

        # 初始化日志显示
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(100)

        # 加载程序设置
        self.load_app_settings()

        self.tunnel_outputs = {}
        self.worker = None
        self.process = None
        self.check_and_download_files()
        self.tunnel_processes = {}

        self.dragging = False
        self.offset = None

        self.set_taskbar_icon()
        self.setup_system_tray()

        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.auto_update)
        self.update_timer.start(30000)  # 30秒更新一次

        self.user_info = None
        self.ddns_active = False
        self.ddns_thread = None
        self.node_list = QWidget()

        self.running_tunnels = {}
        self.running_tunnels_mutex = QMutex()

        self.node_check_timer = QTimer(self)
        self.node_check_timer.timeout.connect(self.check_node_status)
        self.node_check_timer.start(60000)

        # 初始化UI
        self.initUI()

        # 确保在初始化后立即应用主题
        self.apply_theme()

        # 加载凭证和自动登录
        self.load_credentials()
        self.auto_login()

        # 加载用户域名
        self.load_user_domains()


    def initUI(self):
        self.setWindowTitle(APP_NAME+" 程序")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        self.background_frame = QFrame(self)
        self.background_frame.setObjectName("background")
        background_layout = QVBoxLayout(self.background_frame)
        main_layout.addWidget(self.background_frame)

        title_bar = QWidget()
        title_layout = QHBoxLayout(title_bar)
        title_label = QLabel(APP_NAME+" 程序")
        title_layout.addWidget(title_label)
        title_layout.addStretch(1)

        self.settings_button = QPushButton("设置")
        self.settings_button.clicked.connect(self.show_settings)
        title_layout.addWidget(self.settings_button)

        min_button = QPushButton("－")
        min_button.clicked.connect(self.showMinimized)
        close_button = QPushButton("×")
        close_button.clicked.connect(self.close)
        theme_button = QPushButton("切换主题")
        theme_button.clicked.connect(self.toggle_theme)

        title_layout.addWidget(theme_button)
        title_layout.addWidget(min_button)
        title_layout.addWidget(close_button)
        background_layout.addWidget(title_bar)

        content_layout = QHBoxLayout()

        menu_widget = QWidget()
        menu_layout = QVBoxLayout(menu_widget)

        self.user_info_button = QPushButton("用户信息")
        self.tunnel_button = QPushButton("隧道管理")
        self.domain_button = QPushButton("域名管理")
        self.node_button = QPushButton("节点状态")
        self.ddns_button = QPushButton("DDNS管理")
        self.ping_button = QPushButton("Ping工具")
        self.ip_tools_button = QPushButton("IP工具")

        self.user_info_button.clicked.connect(lambda: self.switch_tab("user_info"))
        self.tunnel_button.clicked.connect(lambda: self.switch_tab("tunnel"))
        self.domain_button.clicked.connect(lambda: self.switch_tab("domain"))
        self.node_button.clicked.connect(lambda: self.switch_tab("node"))
        self.ddns_button.clicked.connect(lambda: self.switch_tab("ddns"))
        self.ping_button.clicked.connect(lambda: self.switch_tab("ping"))
        self.ip_tools_button.clicked.connect(lambda: self.switch_tab("ip_tools"))

        menu_layout.addWidget(self.user_info_button)
        menu_layout.addWidget(self.tunnel_button)
        menu_layout.addWidget(self.domain_button)
        menu_layout.addWidget(self.node_button)
        menu_layout.addWidget(self.ddns_button)
        menu_layout.addWidget(self.ping_button)
        menu_layout.addWidget(self.ip_tools_button)
        menu_layout.addStretch(1)

        content_layout.addWidget(menu_widget)

        self.content_stack = QStackedWidget()
        content_layout.addWidget(self.content_stack, 1)

        background_layout.addLayout(content_layout)

        background_layout.addWidget(self.log_display)

        author_info = QLabel("本程序基于ChmlFrp api开发 作者: boring_student")
        author_info.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
        author_info.setStyleSheet("font-size: 7pt; color: #888888; background: transparent; padding: 2px;")
        author_info.setProperty("author_info", True)
        author_info.setFixedHeight(18)

        bottom_layout = QHBoxLayout()
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(author_info)
        bottom_layout.setContentsMargins(0, 0, 5, 2)
        background_layout.addLayout(bottom_layout)

        self.setup_user_info_page()
        self.setup_tunnel_page()
        self.setup_domain_page()
        self.setup_node_page()
        self.setup_ddns_page()
        self.setup_ping_page()
        self.setup_ip_tools_page()

        self.switch_tab("user_info")

        self.tab_buttons = [
            self.user_info_button,
            self.tunnel_button,
            self.domain_button,
            self.node_button,
            self.ddns_button,
            self.ping_button,
            self.ip_tools_button
        ]

    def load_app_settings(self):
        """加载应用程序设置"""
        settings_path = get_absolute_path("settings.json")
        try:
            if os.path.exists(settings_path):
                with open(settings_path, 'r') as f:
                    settings = json.load(f)
                    theme_setting = settings.get('theme', 'system')

                    if theme_setting == 'system':
                        self.dark_theme = self.is_system_dark_theme()
                    elif theme_setting == 'dark':
                        self.dark_theme = True
                    else:  # light
                        self.dark_theme = False

            else:
                self.dark_theme = self.is_system_dark_theme()
                self.logger.info("使用系统默认主题设置")
        except Exception as e:
            self.logger.error(f"加载设置失败: {str(e)}")
            self.dark_theme = self.is_system_dark_theme()

    def setup_system_tray(self):
        icon_path = get_absolute_path("favicon.ico")
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(icon_path))

        tray_menu = QMenu()
        show_action = tray_menu.addAction("显示")
        show_action.triggered.connect(self.show)
        quit_action = tray_menu.addAction("退出")
        quit_action.triggered.connect(self.quit_application)
        self.tray_icon.setContextMenu(tray_menu)

        self.tray_icon.activated.connect(self.tray_icon_activated)

        self.tray_icon.show()

    def auto_start_tunnels(self):
        if not self.token:
            return

        settings_path = get_absolute_path("settings.json")
        try:
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                auto_start_tunnels = settings.get('auto_start_tunnels', [])

            tunnels = get_user_tunnels(self.token)
            if tunnels:
                for tunnel in tunnels:
                    if tunnel['name'] in auto_start_tunnels:
                        self.start_tunnel(tunnel)
                        self.logger.info(f"自动启动隧道: {tunnel['name']}")
        except Exception as e:
            self.logger.error(f"自动启动隧道失败: {str(e)}")

    def show_settings(self):
        dialog = SettingsDialog(self)
        dialog.apply_theme(self.dark_theme)
        dialog.exec()

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()

    def quit_application(self):
        self.cleanup()
        QApplication.quit()

    def set_taskbar_icon(self):
        icon_path = get_absolute_path("favicon.ico")
        self.setWindowIcon(QIcon(icon_path))

    def setup_ip_tools_page(self):
        self.ip_tools_widget = IPToolsWidget()
        self.content_stack.addWidget(self.ip_tools_widget)
        self.ip_tools_widget.update_style(self.dark_theme)

    def check_node_status(self):
        if not self.token:
            self.logger.warning("未登录，无法检查节点状态")
            return

        tunnels = get_user_tunnels(self.token)
        if tunnels is None:
            return

        for tunnel_name, process in list(self.tunnel_processes.items()):
            tunnel_info = next((t for t in tunnels if t['name'] == tunnel_name), None)
            if tunnel_info:
                node_name = tunnel_info['node']
                if not is_node_online(node_name):
                    self.logger.warning(f"节点 {node_name} 离线，停止隧道 {tunnel_name}")
                    self.stop_tunnel({"name": tunnel_name})
                    QMessageBox.warning(self, "节点离线", f"节点 {node_name} 离线，隧道 {tunnel_name} 已停止")
            else:
                self.logger.warning(f"未找到隧道 {tunnel_name} 的信息")

    def update_button_styles(self, selected_button):
        for button in self.tab_buttons:
            if button == selected_button:
                button.setStyleSheet(f"""
					QPushButton {{
						background-color: {self.button_hover_color};
						color: white;
						border: none;
						padding: 5px 10px;
						text-align: center;
						text-decoration: none;
						font-size: 14px;
						margin: 4px 2px;
						border-radius: 4px;
					}}
				""")
            else:
                button.setStyleSheet(f"""
					QPushButton {{
						background-color: {self.button_color};
						color: white;
						border: none;
						padding: 5px 10px;
						text-align: center;
						text-decoration: none;
						font-size: 14px;
						margin: 4px 2px;
						border-radius: 4px;
					}}
					QPushButton:hover {{
						background-color: {self.button_hover_color};
					}}
				""")

    def batch_edit_tunnels(self):
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择要编辑的隧道")
            return

        dialog = BatchEditDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            changes = dialog.get_changes()
            if not changes:
                QMessageBox.information(self, "提示", "没有进行任何修改")
                return

            for tunnel_info in self.selected_tunnels:
                try:
                    url = "http://cf-v2.uapis.cn/update_tunnel"
                    payload = {
                        "tunnelid": int(tunnel_info["id"]),
                        "token": self.token,
                        "tunnelname": tunnel_info["name"],
                        "node": changes.get("node", tunnel_info["node"]),
                        "localip": tunnel_info["localip"],  # 保留原本的 localip，不进行解析
                        "porttype": changes.get("type", tunnel_info["type"]),
                        "localport": tunnel_info["nport"],
                        "remoteport": tunnel_info["dorp"],
                        "encryption": tunnel_info["encryption"],
                        "compression": tunnel_info["compression"]
                    }

                    # 验证本地端口是否有效
                    if "nport" in changes:
                        if not validate_port(changes["nport"]):
                            raise ValueError(f"隧道 '{tunnel_info['name']}': 本地端口必须是1-65535之间的整数")
                        payload["localport"] = int(changes["nport"])

                    # 验证远程端口是否有效
                    if "dorp" in changes:
                        if not validate_port(changes["dorp"]):
                            raise ValueError(f"隧道 '{tunnel_info['name']}': 远程端口必须是10000-65535之间的整数")
                        payload["remoteport"] = int(changes["dorp"])

                    headers = get_headers(json=True)
                    response = requests.post(url, headers=headers, json=payload)
                    if response.status_code == 200:
                        self.logger.info(f"隧道 {tunnel_info['name']} 更新成功")
                    else:
                        self.logger.error(f"更新隧道 {tunnel_info['name']} 失败: {response.text}")
                except ValueError as ve:
                    self.logger.error(str(ve))
                    QMessageBox.warning(self, "错误", str(ve))
                except Exception as e:
                    self.logger.exception(f"更新隧道 {tunnel_info['name']} 时发生错误")
                    QMessageBox.warning(self, "错误", f"更新隧道 {tunnel_info['name']} 失败: {str(e)}")

            self.load_tunnels()  # 刷新隧道列表
            QMessageBox.information(self, "成功", "批量编辑完成")

    def setup_user_info_page(self):
        user_info_widget = QWidget()
        layout = QVBoxLayout(user_info_widget)

        title_label = QLabel("用户信息")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title_label)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('用户名/邮箱')
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('密码')
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_input = QLineEdit(self)
        self.token_input.setPlaceholderText('Token (可选 仅填时为token登录)')
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_button = QPushButton('登录', self)
        self.login_button.clicked.connect(self.login)
        self.logout_button = QPushButton('退出登录', self)
        self.logout_button.clicked.connect(self.logout)
        self.logout_button.setEnabled(False)

        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.token_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.logout_button)

        self.user_info_display = QTextEdit()
        self.user_info_display.setReadOnly(True)
        layout.addWidget(self.user_info_display)

        layout.addStretch(1)

        self.content_stack.addWidget(user_info_widget)

    def on_tunnel_clicked(self, tunnel_info, is_selected):
        if is_selected:
            if tunnel_info not in self.selected_tunnels:
                self.selected_tunnels.append(tunnel_info)
        else:
            self.selected_tunnels = [t for t in self.selected_tunnels if t['id'] != tunnel_info['id']]

        self.update_tunnel_buttons()

    def update_tunnel_buttons(self):
        selected_count = len(self.selected_tunnels)
        self.edit_tunnel_button.setEnabled(selected_count == 1)
        self.delete_tunnel_button.setEnabled(selected_count > 0)
        self.batch_edit_button.setEnabled(selected_count > 0)
        self.view_output_button.setEnabled(selected_count == 1)

    def get_selected_tunnel_count(self):
        count = 0
        layout = self.tunnel_container.layout()
        for i in range(layout.rowCount()):
            for j in range(layout.columnCount()):
                item = layout.itemAtPosition(i, j)
                if item and isinstance(item.widget(), TunnelCard) and item.widget().is_selected:
                    count += 1
        return count

    def on_domain_clicked(self, domain_info):
        for i in range(self.domain_container.layout().count()):
            item = self.domain_container.layout().itemAt(i)
            if item.widget():
                item.widget().setSelected(False)
        self.sender().setSelected(True)
        self.selected_domain = domain_info
        self.edit_domain_button.setEnabled(True)
        self.delete_domain_button.setEnabled(True)

    def setup_tunnel_page(self):
        tunnel_widget = QWidget()
        layout = QVBoxLayout(tunnel_widget)

        # 添加刷新按钮
        button_layout = QHBoxLayout()
        refresh_button = QPushButton("刷新隧道列表")
        refresh_button.clicked.connect(self.load_tunnels)
        button_layout.addWidget(refresh_button)

        # 添加清除frpc进程按钮
        clear_frpc_button = QPushButton("清除frpc进程")
        clear_frpc_button.clicked.connect(self.clear_frpc_processes)
        button_layout.addWidget(clear_frpc_button)

        layout.addLayout(button_layout)

        self.tunnel_container = QWidget()
        self.tunnel_container.setLayout(QGridLayout())

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.tunnel_container)

        layout.addWidget(scroll_area)

        button_layout = QHBoxLayout()
        add_tunnel_button = QPushButton("添加隧道")
        add_tunnel_button.clicked.connect(self.add_tunnel)
        self.edit_tunnel_button = QPushButton("编辑隧道")
        self.edit_tunnel_button.clicked.connect(self.edit_tunnel)
        self.edit_tunnel_button.setEnabled(False)
        self.delete_tunnel_button = QPushButton("删除隧道")
        self.delete_tunnel_button.clicked.connect(self.delete_tunnel)
        self.delete_tunnel_button.setEnabled(False)
        self.batch_edit_button = QPushButton("批量编辑")
        self.batch_edit_button.clicked.connect(self.batch_edit_tunnels)
        self.batch_edit_button.setEnabled(False)

        self.view_output_button = QPushButton("查看输出")
        self.view_output_button.clicked.connect(self.view_output)
        self.view_output_button.setEnabled(False)

        button_layout.addWidget(add_tunnel_button)
        button_layout.addWidget(self.edit_tunnel_button)
        button_layout.addWidget(self.delete_tunnel_button)
        button_layout.addWidget(self.batch_edit_button)
        button_layout.addWidget(self.view_output_button)

        layout.addLayout(button_layout)

        self.content_stack.addWidget(tunnel_widget)

    def clear_frpc_processes(self):
        reply = QMessageBox.question(self, '确认清除frpc进程',
                                     "您确定要清除所有frpc.exe进程吗？",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            reply = QMessageBox.question(self, '再次确认清除frpc进程',
                                         "这将会终止所有frpc.exe进程，您确保所有都准备好了吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    subprocess.run(['taskkill', '/f', '/im', 'frpc.exe'], check=True)
                    self.logger.info("所有frpc.exe进程已被清除")
                except subprocess.CalledProcessError:
                    self.logger.info(f"没有找到frpc进程")

    def view_output(self):
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择一个隧道")
            return

        for tunnel_info in self.selected_tunnels:
            tunnel_name = tunnel_info['name']

            try:
                with QMutexLocker(self.output_mutex):
                    if tunnel_name not in self.tunnel_outputs:
                        QMessageBox.information(self, "提示", "这个隧道还没启动过哦！")
                        continue

                    # 创建新的对话框或显示现有对话框
                    if not self.tunnel_outputs[tunnel_name]['dialog']:
                        self.tunnel_outputs[tunnel_name]['dialog'] = OutputDialog(self)

                    # 更新并显示对话框
                    dialog = self.tunnel_outputs[tunnel_name]['dialog']
                    output_text = self.tunnel_outputs[tunnel_name]['output'].replace('\n', '<br>')
                    dialog.add_output(tunnel_name, output_text,
                                      self.tunnel_outputs[tunnel_name]['run_number'])
                    dialog.show()
                    dialog.raise_()
                    dialog.activateWindow()

            except Exception as e:
                self.logger.error(f"显示输出对话框时发生错误: {str(e)}")
                QMessageBox.warning(self, "错误", f"显示输出时发生错误: {str(e)}")

    def setup_domain_page(self):
        domain_widget = QWidget()
        layout = QVBoxLayout(domain_widget)

        # 添加刷新按钮
        refresh_button = QPushButton("刷新域名列表")
        refresh_button.clicked.connect(self.load_domains)
        layout.addWidget(refresh_button)

        refresh_button = QPushButton("刷新域名列表")
        refresh_button.setObjectName("refreshButton")

        self.domain_container = QWidget()
        self.domain_container.setLayout(QGridLayout())

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.domain_container)

        layout.addWidget(scroll_area)

        button_layout = QHBoxLayout()
        add_domain_button = QPushButton("添加域名")
        add_domain_button.clicked.connect(self.add_domain)
        self.edit_domain_button = QPushButton("编辑域名")
        self.edit_domain_button.clicked.connect(self.edit_domain)
        self.edit_domain_button.setEnabled(False)
        self.delete_domain_button = QPushButton("删除域名")
        self.delete_domain_button.clicked.connect(self.delete_domain)
        self.delete_domain_button.setEnabled(False)
        button_layout.addWidget(add_domain_button)
        button_layout.addWidget(self.edit_domain_button)
        button_layout.addWidget(self.delete_domain_button)

        layout.addLayout(button_layout)

        self.content_stack.addWidget(domain_widget)

    def setup_node_page(self):
        node_widget = QWidget()
        layout = QVBoxLayout(node_widget)

        self.node_container = QWidget()
        self.node_container.setLayout(QGridLayout())

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.node_container)

        layout.addWidget(scroll_area)

        button_layout = QHBoxLayout()

        self.refresh_button = QPushButton("刷新节点状态")
        self.refresh_button.clicked.connect(self.refresh_nodes)
        button_layout.addWidget(self.refresh_button)

        self.details_button = QPushButton("查看详细信息")
        self.details_button.clicked.connect(self.show_node_details)
        self.details_button.setEnabled(False)
        button_layout.addWidget(self.details_button)

        layout.addLayout(button_layout)

        self.content_stack.addWidget(node_widget)

    def setup_ddns_page(self):
        ddns_widget = QWidget()
        layout = QVBoxLayout(ddns_widget)

        # 创建水平布局来容纳下拉框和刷新按钮
        ddns_domain_layout = QHBoxLayout()

        # 添加下拉框
        self.ddns_domain_combo = QComboBox()
        self.ddns_domain_combo.addItem("选择域名")
        self.ddns_domain_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # 创建刷新按钮
        refresh_domain_button = QPushButton()
        refresh_domain_button.setFixedSize(30, 30)
        refresh_domain_button.setIcon(QIcon.fromTheme("view-refresh"))
        refresh_domain_button.setToolTip("刷新域名列表")
        refresh_domain_button.clicked.connect(self.load_user_domains)

        # 将下拉框和按钮添加到水平布局
        layout.addWidget(QLabel("选择DDNS域名:"))
        ddns_domain_layout.addWidget(self.ddns_domain_combo)
        ddns_domain_layout.addWidget(refresh_domain_button)
        layout.addLayout(ddns_domain_layout)

        self.ddns_api_combo = QComboBox()
        self.ddns_api_combo.addItems([
            "ipplus360.com",
            "uapis.cn",
            "v4.ident.me",
            "v6.ident.me"
        ])
        layout.addWidget(QLabel("选择IP获取API:"))
        layout.addWidget(self.ddns_api_combo)

        ipv6_note = QLabel("提示：如果使用IPv6地址，请确保已手动创建AAAA类型的DNS记录。")
        ipv6_note.setWordWrap(True)
        ipv6_note.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(ipv6_note)

        self.ddns_status_label = QLabel("DDNS状态: 未启动")
        layout.addWidget(self.ddns_status_label)

        self.ip_display_label = QLabel("当前IP: 未获取")
        layout.addWidget(self.ip_display_label)

        self.ddns_start_button = QPushButton("启动DDNS")
        self.ddns_start_button.clicked.connect(self.toggle_ddns)
        layout.addWidget(self.ddns_start_button)

        self.content_stack.addWidget(ddns_widget)

    def update_subdomain_combo(self, selected_main_domain):
        self.ddns_domain_combo.clear()
        self.ddns_domain_combo.addItem("选择子域名")
        if selected_main_domain != "选择主域名":
            for domain in self.user_domains:
                if domain['domain'] == selected_main_domain:
                    self.ddns_domain_combo.addItem(domain['record'])

    def setup_ping_page(self):
        ping_widget = QWidget()
        layout = QVBoxLayout(ping_widget)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入目标地址（IP或域名）")
        layout.addWidget(self.target_input)

        ping_type_layout = QHBoxLayout()
        self.ping_type_combo = QComboBox()
        self.ping_type_combo.addItems(["ICMP", "TCP", "HTTP", "HTTPS", "JavaMC", "BedrockMC", "API"])
        ping_type_layout.addWidget(QLabel("Ping类型:"))
        ping_type_layout.addWidget(self.ping_type_combo)
        layout.addLayout(ping_type_layout)

        self.ping_button = QPushButton("开始Ping")
        self.ping_button.clicked.connect(self.start_ping)
        layout.addWidget(self.ping_button)

        self.ping_result = QTextEdit()
        self.ping_result.setReadOnly(True)
        layout.addWidget(self.ping_result)

        self.content_stack.addWidget(ping_widget)

        if hasattr(self, 'api_protocol_combo'):
            self.api_protocol_combo.deleteLater()
            del self.api_protocol_combo

    def on_ping_type_changed(self, ping_type):
        self.api_protocol_combo.setVisible(ping_type == "API")

    def load_credentials(self):
        """加载保存的凭证"""
        credentials_path = get_absolute_path('credentials.json')
        if os.path.exists(credentials_path):
            try:
                with open(credentials_path, 'r') as f:
                    credentials = json.load(f)
                    self.username_input.setText(credentials.get('username', ''))
                    self.password_input.setText(credentials.get('password', ''))
                    self.token_input.setText(credentials.get('token', ''))
            except Exception as e:
                self.logger.error(f"加载凭证时发生错误: {str(e)}")

    def save_credentials(self):
        """保存凭证"""
        credentials = {
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'token': self.token_input.text()
        }
        credentials_path = get_absolute_path('credentials.json')
        try:
            with open(credentials_path, 'w') as f:
                json.dump(credentials, f)
        except Exception as e:
            self.logger.error(f"保存凭证时发生错误: {str(e)}")

    def auto_login(self):
        """自动登录"""
        if self.token_input.text():
            self.token = self.token_input.text()
            self.logger.info("使用保存的Token自动登录")
            self.login_success()
        elif self.username_input.text() and self.password_input.text():
            self.token = login(self.username_input.text(), self.password_input.text())
            if self.token:
                self.logger.info("使用保存的密码自动登录成功")
                self.login_success()
            else:
                self.logger.warning("自动登录失败，请手动登录")

    def login(self):
        """登录功能"""
        token = self.token_input.text()
        if token:
            try:
                url = f"http://cf-v2.uapis.cn/userinfo"
                headers = get_headers()
                params = {
                    "token": token
                }
                response = requests.get(url, params=params, headers=headers)
                data = response.json()
                if data['code'] == 200:
                    self.token = token
                else:
                    self.logger.error(f"Token登录失败: {data.get('msg', '未知错误')}")
                    QMessageBox.warning(self, "登录失败", f"Token登录失败: {data.get('msg', '未知错误')}")
                    return
            except Exception as e:
                self.logger.error(f"Token验证失败: {str(e)}")
                QMessageBox.warning(self, "登录失败", f"Token验证失败: {str(e)}")
                return
        else:
            try:
                url = f"http://cf-v2.uapis.cn/login"
                headers = get_headers()
                params = {
                    "username": self.username_input.text(),
                    "password": self.password_input.text()
                }
                response = requests.get(url, headers=headers, params=params)
                data = response.json()
                if data['code'] == 200:
                    self.token = data['data']['usertoken']
                else:
                    self.logger.error(f"登录失败: {data.get('msg', '未知错误')}")
                    QMessageBox.warning(self, "登录失败", f"登录失败: {data.get('msg', '未知错误')}")
                    return
            except Exception as e:
                self.logger.error(f"登录请求失败: {str(e)}")
                QMessageBox.warning(self, "登录失败", f"登录请求失败: {str(e)}")
                return

        if self.token:
            self.logger.info("登录成功")
            self.save_credentials()
            self.login_success()

    def login_success(self):
        """登录成功后的操作"""
        try:
            self.login_button.setEnabled(False)
            self.logout_button.setEnabled(True)
            self.username_input.setEnabled(False)
            self.password_input.setEnabled(False)
            self.token_input.setEnabled(False)
            self.load_user_data()
            self.load_user_domains()
            self.auto_start_tunnels()
        except Exception as e:
            self.logger.error(f"登录成功后操作失败: {str(e)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(f"登录成功，但加载数据失败: {str(e)}")

    def logout(self):
        """退出登录"""
        # 停止所有使用token的操作
        self.stop_all_api_operations()

        self.token = None
        self.login_button.setEnabled(True)
        self.logout_button.setEnabled(False)
        self.username_input.setEnabled(True)
        self.password_input.setEnabled(True)
        self.token_input.setEnabled(True)
        self.username_input.clear()
        self.password_input.clear()
        self.token_input.clear()

        credentials_path = get_absolute_path('credentials.json')
        try:
            with open(credentials_path, 'w') as f:
                json.dump({}, f)
            self.logger.info("凭证文件已清空")
        except Exception as e:
            self.logger.error(f"清空凭证文件时发生错误: {str(e)}")

        self.clear_user_data()
        self.logger.info("已退出登录")

    def stop_all_api_operations(self):
        """停止所有使用token的API操作"""
        try:
            if self.ddns_active:
                self.stop_ddns()

            for tunnel_name in list(self.tunnel_processes.keys()):
                self.stop_tunnel({"name": tunnel_name})

            QApplication.processEvents()
        except Exception as e:
            self.logger.error(f"停止API操作时发生错误: {str(e)}")

    def load_user_data(self):
        """加载用户数据"""
        try:
            self.user_info = self.get_user_info()
            self.load_tunnels()
            self.load_domains()
            self.load_nodes()
            self.load_user_domains()  # 为DDNS功能加载域名
            self.display_user_info()
        except Exception as e:
            self.logger.error(f"加载用户数据时发生错误: {str(e)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(f"加载用户数据时发生错误: {str(e)}")

    def get_user_info(self):
        """获取用户信息"""
        url = f"http://cf-v2.uapis.cn/userinfo"
        params = {
            "token": self.token
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                Number_of_tunnels = data['data']['tunnelCount']
                return data['data']
            else:
                self.logger.error(f"获取用户信息失败: {data['msg']}")
                return None
        except Exception:
            self.logger.exception("获取用户信息时发生错误")
            return None

    def display_user_info(self):
        if self.user_info['term'] == "9999-09-09":
            self.user_info['term'] = "永久有效"
        """显示用户信息"""
        if self.user_info:
            info_text = f"""
		ID: {self.user_info['id']}
		用户名: {self.user_info['username']}
		注册时间: {self.user_info['regtime']}
		邮箱: {self.user_info['email']}
		实名状态: {self.user_info['realname']}
		用户组: {self.user_info['usergroup']}
		国内带宽: {self.user_info['bandwidth']} Mbps
		国外带宽: {int(self.user_info['bandwidth']) * 4} Mbps
		隧道数量: {self.user_info['tunnelCount']} / {self.user_info['tunnel']}
		积分: {self.user_info['integral']}
		到期时间: {self.user_info['term']}
		上传数据: {self.user_info['total_upload']/1024/1024:.2f}MB
		下载数据: {self.user_info['total_download']/1024/1024:.2f}MB
			"""
            self.user_info_display.setPlainText(info_text)
        else:
            self.user_info_display.setPlainText("无法获取用户信息")

    def clear_all_selections(self):
        layout = self.tunnel_container.layout()
        for i in range(layout.rowCount()):
            for j in range(layout.columnCount()):
                item = layout.itemAtPosition(i, j)
                if item and isinstance(item.widget(), TunnelCard):
                    item.widget().is_selected = False
                    item.widget().setSelected(False)

    def load_tunnels(self):
        """加载隧道列表"""
        try:
            if not self.token:
                self.show_error_message("未登录，无法加载隧道列表")
                return

            tunnels = get_user_tunnels(self.token)
            if tunnels is None:
                return

            # 清除现有的隧道卡片
            while self.tunnel_container.layout().count():
                item = self.tunnel_container.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            if not tunnels:  # 如果隧道列表为空
                self.logger.info("当前没有隧道哦！快点去创建吧！")
                return  # 直接返回，不显示错误

            selected_ids = [t['id'] for t in self.selected_tunnels]

            row, col = 0, 0
            for tunnel in tunnels:
                try:
                    tunnel_widget = TunnelCard(tunnel, self.token)
                    tunnel_widget.clicked.connect(self.on_tunnel_clicked)
                    tunnel_widget.start_stop_signal.connect(self.start_stop_tunnel)

                    if tunnel['id'] in selected_ids:
                        tunnel_widget.is_selected = True
                        tunnel_widget.setSelected(True)

                    self.tunnel_container.layout().addWidget(tunnel_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1

                except Exception as e:
                    self.logger.error(f"创建隧道卡片时发生错误: {str(e)}")
                    self.logger.error(traceback.format_exc())
                    continue

            self.selected_tunnels = [t for t in tunnels if t['id'] in selected_ids]
            self.update_tunnel_buttons()

        except Exception as e:
            self.logger.error(f"加载隧道列表时发生错误: {str(e)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(f"加载隧道列表时发生错误: {str(e)}")

    def clear_error_message(self, widget):
        """清除错误消息"""
        if isinstance(widget, QListWidget):
            for i in range(widget.count()):
                item = widget.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == "error_message":
                    widget.takeItem(i)
                    break

    def show_error_message(self, message, widget=None):
        QMessageBox.warning(self, "错误", message)
        if widget and isinstance(widget, QListWidget):
            self.clear_error_message(widget)
            error_item = QListWidgetItem(message)
            error_item.setData(Qt.ItemDataRole.UserRole, "error_message")
            error_item.setForeground(Qt.GlobalColor.red)
            widget.addItem(error_item)

    def load_domains(self):
        """加载域名列表"""
        try:
            if not self.token:
                raise ValueError("未登录，无法加载域名列表")

            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {
                "token": self.token
            }
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            if data['code'] != 200:
                raise ValueError(data.get('msg'))

            domains = data['data']

            # 清除现有的域名卡片
            while self.domain_container.layout().count():
                item = self.domain_container.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            row, col = 0, 0
            for domain in domains:
                try:
                    domain_widget = DomainCard(domain)
                    domain_widget.clicked.connect(self.on_domain_clicked)
                    self.domain_container.layout().addWidget(domain_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1

                except Exception as e:
                    self.logger.error(f"创建域名卡片时发生错误: {str(e)}")
                    self.logger.error(traceback.format_exc())
                    continue
        except Exception as e:
            self.logger.error(f"获取域名列表时发生错误: {str(e)}")
            self.logger.error(traceback.format_exc())
            self.show_error_message(self.domain_container, f"获取域名列表时发生错误: {str(e)}")

    def load_nodes(self):
        """加载节点列表"""
        try:
            url = "http://cf-v2.uapis.cn/node_stats"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if data['code'] != 200:
                raise ValueError(data.get('msg', '未知错误'))

            nodes = data['data']

            # 清除现有的节点卡片
            while self.node_container.layout().count():
                item = self.node_container.layout().takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            row, col = 0, 0
            for node in nodes:
                try:
                    node_widget = NodeCard(node)
                    node_widget.clicked.connect(self.on_node_clicked)
                    self.node_container.layout().addWidget(node_widget, row, col)

                    col += 1
                    if col == 2:  # 每行两个卡片
                        col = 0
                        row += 1

                except Exception as e:
                    self.logger.error(f"创建节点卡片时发生错误: {str(e)}")
                    continue

        except Exception as e:
            self.logger.error(f"获取节点列表时发生错误: {str(e)}")
            self.show_error_message(self.node_container, f"获取节点列表时发生错误: {str(e)}")

    def on_node_clicked(self, node_info):
        for i in range(self.node_container.layout().count()):
            item = self.node_container.layout().itemAt(i)
            if item.widget():
                item.widget().setSelected(False)
        self.sender().setSelected(True)
        self.selected_node = node_info
        self.details_button.setEnabled(True)

    def show_node_details(self):
        if hasattr(self, 'selected_node'):
            details = self.format_node_details(self.selected_node)
            QMessageBox.information(self, "节点详细信息", details)
        else:
            QMessageBox.warning(self, "警告", "请先选择一个节点")

    def format_node_details(self, node_info):
        details = f"""节点名称: {node_info.get('node_name', 'N/A')}
状态: {'在线' if node_info.get('state') == 'online' else '离线'}
节点组: {node_info.get('nodegroup', 'N/A')}
带宽使用率: {node_info.get('bandwidth_usage_percent', 'N/A')}%
CPU使用率: {node_info.get('cpu_usage', 'N/A')}%
当前连接数: {node_info.get('cur_counts', 'N/A')}
客户端数量: {node_info.get('client_counts', 'N/A')}
总流入流量: {self.format_traffic(node_info.get('total_traffic_in', 0))}
总流出流量: {self.format_traffic(node_info.get('total_traffic_out', 0))}"""
        return details

    def start_stop_tunnel(self, tunnel_info, start):
        if start:
            self.start_tunnel(tunnel_info)
        else:
            self.stop_tunnel(tunnel_info)

        # 更新隧道卡片状态
        self.update_tunnel_card_status(tunnel_info['name'], start)

    def start_tunnel(self, tunnel_info):
        try:
            # 首先检查节点是否在线
            if not is_node_online(tunnel_info['node']):
                QMessageBox.warning(self, "警告", f"节点 {tunnel_info['node']} 当前不在线，无法启动隧道。")
                self.logger.warning(f"尝试启动隧道失败: 节点 {tunnel_info['node']} 不在线")
                return

            frpc_path = get_absolute_path("frpc.exe")
            cmd = [
                frpc_path,
                "-u", self.token,
                "-p", str(tunnel_info['id'])
            ]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.logger.info(f"frpc已启动，使用节点: {tunnel_info['node']}")
            self.tunnel_processes[tunnel_info['name']] = process

            # 捕获输出并存储
            self.capture_output(tunnel_info['name'], process)

            # 更新UI状态
            self.update_tunnel_card_status(tunnel_info['name'], True)

            # 启动状态检查
            QTimer.singleShot(3000, lambda: self.check_tunnel_status(tunnel_info['name']))
        except Exception as e:
            self.logger.exception(f"启动隧道时发生错误: {str(e)}")
            QMessageBox.warning(self, "错误", f"启动隧道失败: {str(e)}")

    def obfuscate_sensitive_data(self, text):
        obfuscated_text = re.sub(re.escape(self.token), '*******你的token********', text, flags=re.IGNORECASE)
        obfuscated_text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                                 lambda x: '{}.***.***.{}'.format(x.group(0).split('.')[0], x.group(0).split('.')[-1]),
                                 obfuscated_text)
        return obfuscated_text

    def render_html(self, text):
        text = re.sub(r'\[I\]', '<span style="color: green;">[I]</span>', text, flags=re.IGNORECASE)
        text = re.sub(r'\[E\]', '<span style="color: red;">[E]</span>', text, flags=re.IGNORECASE)
        text = re.sub(r'\[W\]', '<span style="color: orange;">[W]</span>', text, flags=re.IGNORECASE)
        return text

    def capture_output(self, tunnel_name, process):
        def read_output(pipe, callback):
            try:
                for line in iter(pipe.readline, b''):
                    if not process.poll() is None:  # 检查进程是否已结束
                        break
                    try:
                        callback(line.decode())
                    except Exception as e:
                        self.logger.error(f"处理输出时发生错误: {str(e)}")
            except Exception as e:
                self.logger.error(f"读取输出时发生错误: {str(e)}")
            finally:
                try:
                    pipe.close()
                except Exception as e:
                    self.logger.error(f"关闭管道时发生错误: {str(e)}")


        def update_output(line):
            try:
                with QMutexLocker(self.output_mutex):
                    if tunnel_name in self.tunnel_outputs:
                        obfuscated_line = self.obfuscate_sensitive_data(line)
                        self.tunnel_outputs[tunnel_name]['output'] += self.render_html(obfuscated_line)

                        if (self.tunnel_outputs[tunnel_name]['dialog'] and
                            not self.tunnel_outputs[tunnel_name]['dialog'].isHidden()):
                            try:
                                self.tunnel_outputs[tunnel_name]['dialog'].add_output(
                                    tunnel_name,
                                    self.tunnel_outputs[tunnel_name]['output'],
                                    self.tunnel_outputs[tunnel_name]['run_number']
                                )
                            except Exception as e:
                                self.logger.error(f"更新对话框时发生错误: {str(e)}")
            except Exception as e:
                self.logger.error(f"更新输出时发生错误: {str(e)}")

        # 初始化输出互斥锁
        if not hasattr(self, 'output_mutex'):
            self.output_mutex = QMutex()

        with QMutexLocker(self.output_mutex):
            self.tunnel_outputs[tunnel_name] = {
                'output': '',
                'run_number': self.tunnel_outputs.get(tunnel_name, {}).get('run_number', 0) + 1,
                'dialog': None,
                'process': process
            }

        # 创建并启动输出读取线程
        stdout_thread = threading.Thread(target=read_output, args=(process.stdout, update_output), daemon=True)
        stderr_thread = threading.Thread(target=read_output, args=(process.stderr, update_output), daemon=True)

        stdout_thread.start()
        stderr_thread.start()

        # 启动进程监控
        monitor_thread = threading.Thread(target=self.monitor_process,
                                       args=(tunnel_name, process, stdout_thread, stderr_thread),
                                       daemon=True)
        monitor_thread.start()

    def monitor_process(self, tunnel_name, process, stdout_thread, stderr_thread):
        """监控进程状态"""
        try:
            process.wait()
            exit_code = process.poll()

            # 等待输出线程完成，设置较短的超时时间
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            with QMutexLocker(self.output_mutex):
                if tunnel_name in self.tunnel_outputs:
                    try:
                        if exit_code != 0:
                            error_message = f"\n[E] 进程异常退出，退出代码: {exit_code}\n"
                            if exit_code == -1073741819:  # 0xC0000005
                                error_message += "[E] 进程访问违规 (可能是由于节点离线或网络问题)\n"
                            self.tunnel_outputs[tunnel_name]['output'] += self.render_html(error_message)

                            # 如果对话框正在显示，使用事件循环安全更新
                            if (self.tunnel_outputs[tunnel_name]['dialog'] and
                                    not self.tunnel_outputs[tunnel_name]['dialog'].isHidden()):
                                dialog = self.tunnel_outputs[tunnel_name]['dialog']
                                output = self.tunnel_outputs[tunnel_name]['output']
                                run_number = self.tunnel_outputs[tunnel_name]['run_number']

                                # 使用QMetaObject.invokeMethod安全地更新UI
                                QMetaObject.invokeMethod(dialog, "add_output",
                                                         Qt.ConnectionType.QueuedConnection,
                                                         Q_ARG(str, tunnel_name),
                                                         Q_ARG(str, output),
                                                         Q_ARG(int, run_number))
                    except Exception as e:
                        self.logger.error(f"处理进程输出时发生错误: {str(e)}")
                    finally:
                        # 清理进程引用
                        self.tunnel_outputs[tunnel_name]['process'] = None

            # 从运行中的隧道列表中移除
            if tunnel_name in self.tunnel_processes:
                del self.tunnel_processes[tunnel_name]

            # 安全地更新UI状态
            QMetaObject.invokeMethod(self, "update_tunnel_card_status",
                                     Qt.ConnectionType.QueuedConnection,
                                     Q_ARG(str, tunnel_name),
                                     Q_ARG(bool, False))

        except Exception as e:
            self.logger.error(f"监控进程时发生错误(frpc进程可能已退出)")
            print(e)
            # 确保进程被清理
            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=1)
            except:
                pass

    def update_output(self, tunnel_name, line):
        obfuscated_line = self.obfuscate_sensitive_data(line)
        self.tunnel_outputs[tunnel_name]['output'] += self.render_html(obfuscated_line)

        if self.tunnel_outputs[tunnel_name]['dialog']:
            self.tunnel_outputs[tunnel_name]['dialog'].add_output(tunnel_name,
                                                                  self.tunnel_outputs[tunnel_name]['output'],
                                                                  self.tunnel_outputs[tunnel_name]['run_number'])

    def update_tunnel_card_status(self, tunnel_name, is_running):
        for i in range(self.tunnel_container.layout().count()):
            widget = self.tunnel_container.layout().itemAt(i).widget()
            if isinstance(widget, TunnelCard) and widget.tunnel_info['name'] == tunnel_name:
                widget.is_running = is_running
                widget.update_status()
                break

    def stop_tunnel(self, tunnel_info):
        try:
            process = self.tunnel_processes.get(tunnel_info['name'])
            if process:
                process.terminate()
                process.wait(timeout=5)
                if process.poll() is None:
                    process.kill()
                del self.tunnel_processes[tunnel_info['name']]
                self.logger.info(f"隧道 {tunnel_info['name']} 已停止")
            else:
                self.logger.warning(f"未找到隧道 {tunnel_info['name']} 的运行进程")

            # 更新UI状态
            self.update_tunnel_card_status(tunnel_info['name'], False)
        except Exception as e:
            self.logger.exception(f"停止隧道时发生错误: {str(e)}")

    def check_tunnel_status(self, tunnel_name):
        process = self.tunnel_processes.get(tunnel_name)
        if process and process.poll() is None:
            # 进程仍在运行
            self.update_tunnel_card_status(tunnel_name, True)
            # 继续检查
            QTimer.singleShot(3000, lambda: self.check_tunnel_status(tunnel_name))
        else:
            # 进程已停止
            self.update_tunnel_card_status(tunnel_name, False)
            if tunnel_name in self.tunnel_processes:
                del self.tunnel_processes[tunnel_name]

    def format_traffic(self, traffic_bytes):
        try:
            traffic_bytes = float(traffic_bytes)
            if traffic_bytes < 1024:
                return f"{traffic_bytes:.2f} B"
            elif traffic_bytes < 1024 * 1024:
                return f"{traffic_bytes / 1024:.2f} KB"
            elif traffic_bytes < 1024 * 1024 * 1024:
                return f"{traffic_bytes / (1024 * 1024):.2f} MB"
            else:
                return f"{traffic_bytes / (1024 * 1024 * 1024):.2f} GB"
        except (ValueError, TypeError):
            return "N/A"

    def clear_user_data(self):
        """清除用户数据"""
        try:
            # 清除隧道列表
            self.clear_layout(self.tunnel_container.layout())

            # 清除域名列表
            self.clear_layout(self.domain_container.layout())

            # 清除节点列表
            self.clear_layout(self.node_container.layout())

            # 清除用户信息显示
            self.user_info_display.clear()

            # 重置其他相关状态
            self.selected_tunnels = []
            self.selected_domain = None
            self.selected_node = None

            self.logger.info("用户数据已清除")
        except Exception as e:
            self.logger.error(f"清除用户数据时发生错误: {str(e)}")

    def clear_layout(self, layout):
        """清除布局中的所有项目"""
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
                else:
                    self.clear_layout(item.layout())

    def add_tunnel(self):
        """添加隧道"""
        dialog = QDialog(self)
        dialog.setWindowTitle("添加隧道")
        dialog.setFixedWidth(750)
        layout = QHBoxLayout(dialog)

        form_layout = QFormLayout()
        detail_layout = QVBoxLayout()

        name_input = QLineEdit()
        name_input.setPlaceholderText("若留空则随机")
        local_ip_input = QLineEdit("127.0.0.1")  # 默认值设置为127.0.0.1
        local_port_input = QLineEdit()
        remote_port_input = QLineEdit()
        remote_port_input.setPlaceholderText("若留空则随机(10000-65535)")  # 添加占位符提示
        banddomain_input = QLineEdit()
        node_combo = QComboBox()
        type_combo = QComboBox()
        encryption_checkbox = QCheckBox("开启加密")
        compression_checkbox = QCheckBox("开启压缩")
        extra_params_input = QLineEdit()
        extra_params_input.setPlaceholderText("额外参数（可选）")

        # 获取节点列表
        nodes = get_nodes()
        for node in nodes:
            node_combo.addItem(node['name'])

        type_combo.addItems(["tcp", "udp", "http", "https"])

        remote_port_label = QLabel("远程端口:")
        banddomain_label = QLabel("绑定域名:")

        form_layout.addRow("隧道名称:", name_input)
        form_layout.addRow("本地IP/主机名:", local_ip_input)
        form_layout.addRow("本地端口:", local_port_input)
        form_layout.addRow(remote_port_label, remote_port_input)
        form_layout.addRow(banddomain_label, banddomain_input)
        form_layout.addRow("节点:", node_combo)
        form_layout.addRow("类型:", type_combo)
        form_layout.addRow(encryption_checkbox)
        form_layout.addRow(compression_checkbox)
        form_layout.addRow("额外参数:", extra_params_input)

        # 初始化控件状态
        banddomain_label.hide()
        banddomain_input.hide()

        def on_type_changed():
            porttype = type_combo.currentText()

            if porttype in ["tcp", "udp"]:
                remote_port_label.show()
                remote_port_input.show()
                banddomain_label.hide()
                banddomain_input.hide()
            else:
                remote_port_label.hide()
                remote_port_input.hide()
                banddomain_label.show()
                banddomain_input.show()

            dialog.adjustSize()

        type_combo.currentTextChanged.connect(on_type_changed)
        on_type_changed()  # 初始化时调用一次

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form_layout.addRow(buttons)

        # 添加详细信息区域
        detail_label = QLabel("节点详细信息")
        detail_text = QTextEdit()
        detail_text.setReadOnly(True)
        detail_layout.addWidget(detail_label)
        detail_layout.addWidget(detail_text)

        layout.addLayout(form_layout)
        layout.addLayout(detail_layout)

        def on_node_changed(index):
            node_name = node_combo.itemText(index)
            for node in nodes:
                if node['name'] == node_name:
                    detail_text.setPlainText(f"""
                        节点名称: {node['name']}
                        节点地址: {node['area']}
                        权限组: {node['nodegroup']}
                        是否属于大陆带宽节点: {node['china']}
                        是否支持web: {node['web']}
                        是否支持udp: {node['udp']}
                        是否有防御: {node['fangyu']}
                        介绍: {node['notes']}
                        """)
                    break

        node_combo.currentIndexChanged.connect(on_node_changed)
        on_node_changed(0)  # 初始化时调用一次

        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                url = "http://cf-v2.uapis.cn/create_tunnel"

                # 生成随机隧道名称（如果未指定）
                tunnel_name = name_input.text()
                if not tunnel_name:
                    tunnel_name = ''.join(
                        random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))

                porttype = type_combo.currentText()
                payload = {
                    "token": self.token,
                    "tunnelname": tunnel_name,
                    "node": node_combo.currentText(),
                    "localip": local_ip_input.text(),
                    "porttype": porttype,
                    "localport": int(local_port_input.text()),
                    "encryption": encryption_checkbox.isChecked(),
                    "compression": compression_checkbox.isChecked(),
                    "extraparams": extra_params_input.text() or ""
                }

                if porttype in ["tcp", "udp"]:
                    remote_port = remote_port_input.text()
                    if not remote_port:  # 如果远程端口为空，则随机生成
                        remote_port = str(random.randint(10000, 65535))
                    if not validate_port(remote_port):
                        raise ValueError("远程端口必须是10000-65535之间的整数")
                    payload["remoteport"] = int(remote_port)
                elif porttype in ["http", "https"]:
                    if not banddomain_input.text():
                        raise ValueError("绑定域名是必须的")
                    payload["banddomain"] = banddomain_input.text()

                headers = get_headers(json=True)
                response = requests.post(url, headers=headers, json=payload)
                response_data = response.json()
                if response.status_code == 200:
                    self.logger.info(f"信息: {response_data.get('msg', '无额外信息')}")
                    QMessageBox.information(self, "成功", f"信息: {response_data.get('msg')}")
                    self.load_tunnels()  # 刷新隧道列表
                else:
                    self.logger.error(f"添加隧道失败: {response_data.get('msg')}")
                    QMessageBox.warning(self, "错误", f"添加隧道失败: {response_data.get('msg')}")
            except ValueError as ve:
                self.logger.error(f"添加隧道失败: {str(ve)}")
                QMessageBox.warning(self, "错误", str(ve))
            except Exception as e:
                self.logger.exception("添加隧道时发生错误")
                QMessageBox.warning(self, "错误", f"添加隧道失败: {str(e)}")

    def edit_tunnel(self):
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择一个隧道")
            return

        if len(self.selected_tunnels) > 1:
            QMessageBox.warning(self, "警告", "编辑隧道时只能选择一个隧道")
            return

        tunnel_info = self.selected_tunnels[0]
        dialog = QDialog(self)
        dialog.setWindowTitle("编辑隧道")
        layout = QFormLayout(dialog)

        name_input = QLineEdit(tunnel_info['name'])
        local_ip_input = QLineEdit(tunnel_info['localip'])
        local_port_input = QLineEdit(str(tunnel_info['nport']))
        remote_port_input = QLineEdit(str(tunnel_info['dorp']))
        node_combo = QComboBox()
        type_combo = QComboBox()
        encryption_checkbox = QCheckBox("开启加密")
        compression_checkbox = QCheckBox("开启压缩")
        extra_params_input = QLineEdit(tunnel_info.get("extraparams", ""))
        extra_params_input.setPlaceholderText("额外参数（可选）")

        encryption_checkbox.setChecked(bool(tunnel_info.get("encryption", False)))
        compression_checkbox.setChecked(bool(tunnel_info.get("compression", False)))

        nodes = get_nodes()
        for node in nodes:
            node_combo.addItem(node['name'])
        node_combo.setCurrentText(tunnel_info['node'])

        type_combo.addItems(["tcp", "udp", "http", "https"])
        type_combo.setCurrentText(tunnel_info['type'])

        layout.addRow("隧道名称:", name_input)
        layout.addRow("本地IP/主机名:", local_ip_input)
        layout.addRow("本地端口:", local_port_input)
        layout.addRow("远程端口:", remote_port_input)
        layout.addRow("节点:", node_combo)
        layout.addRow("类型:", type_combo)
        layout.addRow(encryption_checkbox)
        layout.addRow(compression_checkbox)
        layout.addRow("额外参数:", extra_params_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                url = "http://cf-v2.uapis.cn/update_tunnel"

                local_ip = local_ip_input.text()  # 直接使用输入的本地IP或主机名

                payload = {
                    "tunnelid": tunnel_info["id"],  # tunnelid 不可修改
                    "token": self.token,  # token 不可修改
                    "tunnelname": name_input.text(),
                    "node": node_combo.currentText(),
                    "localip": local_ip,  # 使用直接输入的IP/主机名
                    "porttype": type_combo.currentText(),
                    "localport": int(local_port_input.text()),
                    "remoteport": int(remote_port_input.text()),
                    "encryption": encryption_checkbox.isChecked(),
                    "compression": compression_checkbox.isChecked(),
                    "extraparams": extra_params_input.text() or ""
                }

                # 校验端口
                if not validate_port(local_port_input.text()) or not validate_port(remote_port_input.text()):
                    QMessageBox.warning(self, "错误", "端口必须是1-65535之间的整数")
                    return

                headers = get_headers(json=True)
                response = requests.post(url, headers=headers, json=payload)
                if response.status_code == 200:
                    self.logger.info("隧道更新成功")
                    self.load_tunnels()  # 刷新隧道列表
                else:
                    self.logger.error(f"更新隧道失败: {response.text}")
            except ValueError as ve:
                self.logger.error(f"更新隧道失败: {str(ve)}")
                QMessageBox.warning(self, "错误", str(ve))
            except Exception as e:
                self.logger.exception("更新隧道时发生错误")
                QMessageBox.warning(self, "错误", f"更新隧道失败: {str(e)}")

    def delete_tunnel(self):
        """删除隧道"""
        if not self.selected_tunnels:
            QMessageBox.warning(self, "警告", "请先选择要删除的隧道")
            return

        tunnels_to_delete = self.selected_tunnels.copy()

        try:
            url = f"http://cf-v2.uapis.cn/userinfo?token={self.token}"
            response = requests.get(url)
            if response.status_code == 200:
                user_info = response.json()
                if user_info["code"] == 200:
                    user_id = user_info["data"]["id"]
                    user_token = user_info["data"]["usertoken"]
                else:
                    raise Exception(f"Failed to get user info from v2: {user_info['msg']}")
            else:
                raise Exception(f"Failed to fetch user info, status code {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error fetching user info: {str(e)}")
            QMessageBox.warning(self, "错误", f"无法获取用户信息: {str(e)}")
            return

        for tunnel_info in tunnels_to_delete:
            time.sleep(0.8)  # 避免频繁请求导致服务器拒绝连接
            reply = QMessageBox.question(self, '确认删除', f"确定要删除隧道 '{tunnel_info['name']}' 吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.Yes:
                try:
                    url_v2 = f"http://cf-v2.uapis.cn/deletetunnel"
                    params = {"token": self.token, "tunnelid": tunnel_info["id"]}
                    headers = get_headers()
                    response = requests.post(url_v2, headers=headers, params=params)
                    if response.status_code == 200:
                        self.logger.info(f"隧道 '{tunnel_info['name']}' 删除成功 (v2 API)")
                        self.selected_tunnels.remove(tunnel_info)
                    else:
                        self.logger.error(f"v2 API 删除隧道失败")
                        raise Exception(f"v2 API 删除失败")
                except Exception:
                    self.logger.error(f"v2 API 删除失败，尝试 v1 API...")
                    try:
                        url_v1 = f"http://cf-v1.uapis.cn/api/deletetl.php"
                        params = {
                            "token": user_token,
                            "userid": user_id,
                            "nodeid": tunnel_info["id"],
                        }
                        headers = get_headers()
                        response_v1 = requests.get(url_v1, params=params, headers=headers)
                        if response_v1.status_code == 200:
                            self.logger.info(f"隧道 '{tunnel_info['name']}' 删除成功 (v1 API)")
                            self.selected_tunnels.remove(tunnel_info)  # 从选中列表中移除
                        else:
                            self.logger.error(f"v1 API 删除隧道失败: {response_v1.text}")
                            raise Exception(f"v1 API 删除失败: {response_v1.text}")
                    except Exception as e_v1:
                        self.logger.exception("删除隧道时发生错误")
                        QMessageBox.warning(self, "错误", f"删除隧道失败: {str(e_v1)}")

        self.load_tunnels()  # 刷新隧道列表
        self.update_tunnel_buttons()  # 更新按钮状态

    def add_domain(self):
        TTL_OPTIONS = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]
        dialog = QDialog(self)
        dialog.setWindowTitle("添加域名")
        layout = QFormLayout(dialog)

        main_domain_combo = QComboBox()
        self.load_main_domains(main_domain_combo)
        record_input = QLineEdit()
        type_combo = QComboBox()
        type_combo.addItems(["A", "AAAA", "CNAME", "SRV"])
        target_input = QLineEdit()
        ttl_combo = QComboBox()
        ttl_combo.addItems(TTL_OPTIONS)
        ttl_combo.setCurrentText("1分钟")

        # SRV输入
        srv_widget = QWidget()
        srv_layout = QFormLayout(srv_widget)
        priority_input = QLineEdit("10")
        weight_input = QLineEdit("10")
        port_input = QLineEdit()
        srv_layout.addRow("优先级:", priority_input)
        srv_layout.addRow("权重:", weight_input)
        srv_layout.addRow("端口:", port_input)
        srv_widget.hide()

        layout.addRow("主域名:", main_domain_combo)
        layout.addRow("子域名:", record_input)
        layout.addRow("类型:", type_combo)
        layout.addRow("目标:", target_input)
        layout.addRow("TTL:", ttl_combo)
        layout.addRow(srv_widget)

        ttl_note = QLabel("注意：较慢的TTL可以提升解析稳定度，但会延长更新生效时间。")
        ttl_note.setWordWrap(True)
        layout.addRow(ttl_note)

        def on_type_changed():
            record_type = type_combo.currentText()
            srv_widget.setVisible(record_type == "SRV")
            if record_type == "SRV":
                target_input.setPlaceholderText("域名或IP")
            elif record_type == "CNAME":
                target_input.setPlaceholderText("目标域名")
            else:
                target_input.setPlaceholderText("IP地址")

        type_combo.currentTextChanged.connect(on_type_changed)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            record_type = type_combo.currentText()
            target = remove_http_https(target_input.text().strip())

            if record_type == "A":
                if is_valid_domain(target):
                    reply = QMessageBox.question(self, "域名输入",
                                                 "您输入了一个域名。您希望如何处理？yes=解析:no=切换到CNAME",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                 QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        # 用户选择解析为 IPv4
                        try:
                            ip = socket.gethostbyname(target)
                            if is_valid_ipv4(ip):
                                target = ip
                            elif is_valid_ipv6(ip):
                                ipv6_reply = QMessageBox.question(self, "IPv6 检测",
                                                                  "解析结果是 IPv6 地址。是否要切换到 AAAA 记录？",
                                                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                if ipv6_reply == QMessageBox.StandardButton.Yes:
                                    record_type = "AAAA"
                                    target = ip
                                else:
                                    QMessageBox.warning(self, "解析失败", "无法将域名解析为 IPv4 地址")
                                    return
                            else:
                                raise Exception("解析失败")
                        except Exception:
                            cname_reply = QMessageBox.question(self, "解析失败",
                                                               "无法将域名解析为 IP 地址。是否要切换到 CNAME 记录？",
                                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                            if cname_reply == QMessageBox.StandardButton.Yes:
                                record_type = "CNAME"
                            else:
                                return
                    else:
                        # 用户选择使用 CNAME
                        record_type = "CNAME"
                elif is_valid_ipv6(target):
                    reply = QMessageBox.question(self, "IPv6地址检测",
                                                 "检测到IPv6地址。是否要切换到AAAA记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "AAAA"
                    else:
                        QMessageBox.warning(self, "无效IP", "A记录必须使用IPv4地址")
                        return
                elif not is_valid_ipv4(target):
                    QMessageBox.warning(self, "无效 IP", "请输入有效的 IPv4 地址")
                    return

            elif record_type == "AAAA":
                if is_valid_ipv4(target):
                    reply = QMessageBox.question(self, "IPv4地址检测",
                                                 "检测到IPv4地址。是否要切换到A记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "A"
                    else:
                        QMessageBox.warning(self, "无效IP", "AAAA记录必须使用IPv6地址")
                        return
                elif is_valid_domain(target):
                    reply = QMessageBox.question(self, "域名输入",
                                                 "您输入了一个域名。您希望如何处理？yes=解析:no=切换到CNAME",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                                 QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        # 用户选择解析为 IPv6
                        try:
                            ip = socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]
                            if is_valid_ipv6(ip):
                                target = ip
                            elif is_valid_ipv4(ip):
                                ipv4_reply = QMessageBox.question(self, "IPv4 检测",
                                                                  "解析结果是 IPv4 地址。是否要切换到 A 记录？",
                                                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                                if ipv4_reply == QMessageBox.StandardButton.Yes:
                                    record_type = "A"
                                    target = ip
                                else:
                                    QMessageBox.warning(self, "解析失败", "无法将域名解析为 IPv6 地址")
                                    return
                            else:
                                raise Exception("解析失败")
                        except Exception as e:
                            cname_reply = QMessageBox.question(self, "解析失败",
                                                               "无法将域名解析为 IP 地址。是否要切换到 CNAME 记录？",
                                                               QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                            if cname_reply == QMessageBox.StandardButton.Yes:
                                record_type = "CNAME"
                            else:
                                return
                    else:
                        # 用户选择使用 CNAME
                        record_type = "CNAME"
                elif not is_valid_ipv6(target):
                    QMessageBox.warning(self, "无效 IP", "请输入有效的 IPv6 地址")
                    return

            elif record_type == "CNAME":
                if is_valid_ipv4(target):
                    reply = QMessageBox.question(self, "IPv4 地址检测",
                                                 "检测到 IPv4 地址。是否要切换到 A 记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "A"
                    else:
                        QMessageBox.warning(self, "无效 CNAME", "CNAME 记录不能指向 IP 地址")
                        return
                elif is_valid_ipv6(target):
                    reply = QMessageBox.question(self, "IPv6 地址检测",
                                                 "检测到 IPv6 地址。是否要切换到 AAAA 记录？",
                                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                    if reply == QMessageBox.StandardButton.Yes:
                        record_type = "AAAA"
                    else:
                        QMessageBox.warning(self, "无效 CNAME", "CNAME 记录不能指向 IP 地址")
                        return
                elif not is_valid_domain(target):
                    QMessageBox.warning(self, "无效域名", "请输入有效的域名")
                    return

            elif record_type == "SRV":
                if not all(x.isdigit() and 0 <= int(x) <= 65535 for x in
                           [priority_input.text(), weight_input.text(), port_input.text()]):
                    QMessageBox.warning(self, "无效SRV参数", "优先级、权重和端口必须是0-65535之间的整数")
                    return

                srv_target = target
                if ':' in srv_target:  # 可能是IPv6
                    srv_target = f"[{srv_target}]"

                # 检查目标是否带有端口
                if ':' in srv_target.strip('[]'):
                    srv_target, srv_port = srv_target.rsplit(':', 1)
                    if not port_input.text():
                        port_input.setText(srv_port)
                    srv_target = srv_target.strip('[]')

                if is_valid_domain(srv_target):
                    srv_target = remove_http_https(srv_target)
                elif not (is_valid_ipv4(srv_target) or is_valid_ipv6(srv_target)):
                    QMessageBox.warning(self, "无效SRV目标", "SRV目标必须是有效的域名或IP地址")
                    return

                target = f"{priority_input.text()} {weight_input.text()} {port_input.text()} {srv_target}"

            try:
                url = "http://cf-v2.uapis.cn/create_free_subdomain"
                payload = {
                    "token": self.token,
                    "domain": main_domain_combo.currentText(),
                    "record": record_input.text(),
                    "type": record_type,
                    "ttl": ttl_combo.currentText(),
                    "target": target,
                    "remarks": ""
                }

                headers = get_headers(json=True)
                response = requests.post(url, headers=headers, json=payload)
                response = response.json()
                if response.status_code == 200:
                    self.logger.info(response["msg"])
                    self.load_domains()  # 刷新域名列表
                else:
                    self.logger.error(f"添加域名失败: {response["msg"]}")
                    QMessageBox.warning(self, "错误", f"添加域名失败: {response["msg"]}")
            except Exception as e:
                self.logger.exception("添加域名时发生错误")
                QMessageBox.warning(self, "错误", f"添加域名失败: {str(e)}")

    def load_main_domains(self, combo_box):
        """加载主域名到下拉框"""
        try:
            url = "http://cf-v2.uapis.cn/list_available_domains"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    combo_box.clear()
                    for domain_info in data['data']:
                        combo_box.addItem(domain_info['domain'])
                else:
                    self.logger.error(f"获取主域名失败: {data['msg']}")
            else:
                self.logger.error(f"获取主域名请求失败: 状态码 {response.status_code}")
        except Exception:
            self.logger.exception("加载主域名时发生错误")

    def get_available_main_domains(self):
        """获取可用的主域名列表"""
        try:
            url = "http://cf-v2.uapis.cn/list_available_domains"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    return [domain_info['domain'] for domain_info in data['data']]
            self.logger.error("获取可用主域名失败")
            return []
        except Exception as e:
            self.logger.exception("获取可用主域名时发生错误")
            return []

    def edit_domain(self):
        """编辑域名 - 仅允许修改 TTL 和目标"""
        TTL_OPTIONS = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]

        if hasattr(self, 'selected_domain'):
            domain_info = self.selected_domain
            dialog = QDialog(self)
            dialog.setWindowTitle("编辑域名")
            layout = QFormLayout(dialog)

            # 只读字段
            domain_label = QLabel(domain_info['domain'])
            record_label = QLabel(domain_info['record'])
            type_label = QLabel(domain_info['type'])

            # 可编辑字段
            target_input = QLineEdit(domain_info['target'])
            ttl_combo = QComboBox()
            ttl_combo.addItems(TTL_OPTIONS)
            ttl_combo.setCurrentText(domain_info['ttl'])

            # 添加字段到布局
            layout.addRow("域名:", domain_label)
            layout.addRow("记录:", record_label)
            layout.addRow("类型:", type_label)
            layout.addRow("目标:", target_input)
            layout.addRow("TTL:", ttl_combo)

            ttl_note = QLabel("注意：较慢的TTL可以提升解析稳定度，但会延长更新生效时间。")
            ttl_note.setWordWrap(True)
            layout.addRow(ttl_note)

            srv_widget = QWidget()
            srv_layout = QFormLayout(srv_widget)
            priority_input = QLineEdit()
            weight_input = QLineEdit()
            port_input = QLineEdit()

            if domain_info['type'] == "SRV":
                priority, weight, port, srv_target = parse_srv_target(domain_info['target'])
                priority_input.setText(priority or "")
                weight_input.setText(weight or "")
                port_input.setText(port or "")
                target_input.setText(srv_target)

                srv_layout.addRow("优先级:", priority_input)
                srv_layout.addRow("权重:", weight_input)
                srv_layout.addRow("端口:", port_input)
                srv_widget.setVisible(True)
                layout.addRow(srv_widget)

            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addRow(buttons)

            if dialog.exec() == QDialog.DialogCode.Accepted:
                record_type = domain_info['type']
                target = remove_http_https(target_input.text().strip())

                # 验证输入
                if record_type == "A" and not is_valid_ipv4(target):
                    QMessageBox.warning(self, "无效IP", "请输入有效的IPv4地址")
                    return
                elif record_type == "AAAA" and not is_valid_ipv6(target):
                    QMessageBox.warning(self, "无效IP", "请输入有效的IPv6地址")
                    return
                elif record_type == "CNAME":
                    if is_valid_ipv4(target) or is_valid_ipv6(target):
                        QMessageBox.warning(self, "无效CNAME", "CNAME记录不能指向IP地址")
                        return
                    elif not is_valid_domain(target):
                        QMessageBox.warning(self, "无效域名", "请输入有效的目标域名")
                        return
                elif record_type == "SRV":
                    if not all(x.isdigit() and 0 <= int(x) <= 65535 for x in
                               [priority_input.text(), weight_input.text(), port_input.text()]):
                        QMessageBox.warning(self, "无效SRV参数", "优先级、权重和端口必须是0-65535之间的整数")
                        return

                    srv_target = target
                    if ':' in srv_target:  # 可能是IPv6
                        srv_target = f"[{srv_target}]"

                    if not is_valid_domain(srv_target) and not is_valid_ipv4(srv_target) and not is_valid_ipv6(
                            srv_target.strip('[]')):
                        QMessageBox.warning(self, "无效SRV目标", "SRV目标必须是有效的域名或IP地址")
                        return

                    target = f"{priority_input.text()} {weight_input.text()} {port_input.text()} {srv_target}"

                try:
                    url = "http://cf-v2.uapis.cn/update_free_subdomain"
                    payload = {
                        "token": self.token,
                        "domain": domain_info['domain'],
                        "record": domain_info['record'],
                        "type": record_type,
                        "ttl": ttl_combo.currentText(),
                        "target": target,
                        "remarks": domain_info.get('remarks', '')
                    }

                    headers = get_headers(json=True)
                    response = requests.post(url, headers=headers, json=payload)
                    if response.status_code == 200:
                        self.logger.info("域名更新成功")
                        self.load_domains()  # 刷新域名列表
                    else:
                        self.logger.error(f"更新域名失败: {response.text}")
                        QMessageBox.warning(self, "错误", f"更新域名失败: {response.text}")
                except Exception as e:
                    self.logger.exception("更新域名时发生错误")
                    QMessageBox.warning(self, "错误", f"更新域名失败: {str(e)}")
        else:
            QMessageBox.warning(self, "警告", "请先选择一个域名")

    def delete_domain(self):
        """删除域名"""
        if hasattr(self, 'selected_domain'):
            domain_info = self.selected_domain
            reply = QMessageBox.question(self, '确认删除',
                                         f"确定要删除域名 '{domain_info['record']}.{domain_info['domain']}' 吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.Yes:
                try:
                    url = "http://cf-v2.uapis.cn/delete_free_subdomain"
                    payload = {
                        "token": self.token,
                        "domain": domain_info['domain'],
                        "record": domain_info['record']
                    }

                    headers = get_headers(json=True)
                    response = requests.post(url, headers=headers, json=payload)
                    if response.status_code == 200:
                        self.logger.info(f"域名 '{domain_info['record']}.{domain_info['domain']}' 删除成功")
                        self.load_domains()  # 刷新域名列表
                    else:
                        self.logger.error(f"删除域名失败: {response.text}")
                except Exception as e:
                    self.logger.exception("删除域名时发生错误")
                    QMessageBox.warning(self, "错误", f"删除域名失败: {str(e)}")
        else:
            QMessageBox.warning(self, "警告", "请先选择一个域名")

    def start_ddns(self, selected_domain):
        if not selected_domain or selected_domain == "选择域名":
            QMessageBox.warning(self, "警告", "请选择一个有效的域名")
            return
        self.ddns_domain = selected_domain
        self.ddns_active = True
        self.ddns_status_label.setText("DDNS状态: 已启动")
        self.ddns_start_button.setText("停止DDNS")
        self.ddns_thread = threading.Thread(target=self.ddns_check_loop, daemon=True)
        self.ddns_thread.start()

    def get_current_ip(self):
        selected_api = self.ddns_api_combo.currentText()
        api_list = [selected_api]  # 首先尝试用户选择的API

        # 如果选择的API失败，再尝试其他API
        all_apis = [
            "ipplus360.com",
            "uapis.cn",
            "v4.ident.me",
            "v6.ident.me"
        ]
        api_list.extend([api for api in all_apis if api != selected_api])

        for api in api_list:
            try:
                ip = self.fetch_ip_from_api(api)
                if ip:
                    ip_type = "IPv4" if is_valid_ipv4(ip) else "IPv6" if is_valid_ipv6(ip) else "Invalid"
                    self.ip_display_label.setText(f"当前IP: {ip} (来自 {api})")
                    return ip, ip_type
            except Exception as e:
                self.logger.error(f"从 {api} 获取IP地址时发生错误: {str(e)}")

        self.ip_display_label.setText("当前IP: 获取失败")
        return None, None

    def fetch_ip_from_api(self, api):
        if api == "ipplus360.com":
            response = requests.get("https://ipplus360.com/getIP")
            data = response.json()
            return data['data']
        elif api == "uapis.cn":
            response = requests.get("https://uapis.cn/api/myip.php")
            data = response.json()
            return data['ip']
        elif api == "v4.ident.me":
            response = requests.get("https://v4.ident.me")
            return response.text.strip()
        elif api == "v6.ident.me":
            response = requests.get("https://v6.ident.me")
            return response.text.strip()
        else:
            raise ValueError(f"未知的API选择: {api}")

    def ddns_check_loop(self):
        last_ip = ""
        while self.ddns_active:
            try:
                current_ip, ip_type = self.get_current_ip()
                if current_ip and current_ip != last_ip:
                    if self.update_ddns(current_ip, ip_type):
                        last_ip = current_ip
                    else:
                        self.logger.info("DDNS更新失败，将在下一次循环重试")
            except Exception as e:
                self.logger.error(f"DDNS更新错误: {str(e)}")

            # 每秒检查一次是否应该停止
            for _ in range(6):  # 60 秒的总循环
                if not self.ddns_active:
                    return  # 如果 ddns_active 为 False，立即退出循环
                time.sleep(1)  # 睡眠 1 秒

    def update_ddns(self, ip, ip_type):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = "http://cf-v2.uapis.cn/update_free_subdomain"
                domain_parts = self.ddns_domain.split(".")
                subdomain = ".".join(domain_parts[:-2])
                main_domain = ".".join(domain_parts[-2:])

                # 获取当前域名的解析类型
                current_record_type = self.get_current_record_type(main_domain, subdomain)

                if current_record_type == "A" and ip_type != "IPv4":
                    self.logger.warning("当前IP不是IPv4地址，尝试获取新的IP")
                    return False
                elif current_record_type == "AAAA" and ip_type != "IPv6":
                    self.logger.warning("当前IP不是IPv6地址，尝试获取新的IP")
                    return False
                elif current_record_type == "CNAME":
                    self.logger.error("CNAME记录不支持DDNS更新")
                    QMessageBox.warning(self, "错误", "CNAME记录不支持DDNS更新")
                    return False
                elif current_record_type == "SRV":
                    # 获取现有的SRV记录
                    existing_srv = self.get_existing_srv_record(main_domain, subdomain)
                    if existing_srv:
                        priority, weight, port, _ = existing_srv.split()
                        target = f"{priority} {weight} {port} {ip}"
                    else:
                        self.logger.error("无法获取现有的SRV记录")
                        return False
                else:
                    target = ip

                payload = {
                    "token": self.token,
                    "domain": main_domain,
                    "record": subdomain,
                    "ttl": "1分钟",
                    "type": current_record_type,
                    "target": target
                }

                headers = get_headers(json=True)
                response = requests.post(url, headers=headers, json=payload)
                response.raise_for_status()

                self.logger.info(f"DDNS更新成功: {self.ddns_domain} -> {ip}")
                self.ddns_status_label.setText(f"DDNS状态: 已更新 ({ip})")
                return True
            except requests.exceptions.RequestException as e:
                self.logger.error(f"DDNS更新失败 (尝试 {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) + random.random()
                    self.logger.info(f"等待 {wait_time:.2f} 秒后重试...")
                    time.sleep(wait_time)
                else:
                    self.ddns_status_label.setText("DDNS状态: 更新失败")
                    self.logger.error(f"DDNS更新失败，达到最大重试次数")

        self.ddns_status_label.setText("DDNS状态: 更新失败")
        return False

    def get_current_record_type(self, domain, record):
        url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
        params = {
            "token": self.token
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                for subdomain in data['data']:
                    if subdomain['domain'] == domain and subdomain['record'] == record:
                        return subdomain['type']
        except Exception as e:
            self.logger.error(f"获取域名记录类型时发生错误: {str(e)}")
        return None

    def get_existing_srv_record(self, domain, record):
        url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
        params = { "token": self.token }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            if data['code'] == 200:
                for subdomain in data['data']:
                    if subdomain['domain'] == domain and subdomain['record'] == record and subdomain['type'] == 'SRV':
                        return subdomain['target']
        except Exception as e:
            self.logger.error(f"获取SRV记录时发生错误: {str(e)}")
        return None

    def start_ping(self):
        target = self.target_input.text().strip()
        ping_type = self.ping_type_combo.currentText()

        if not target:
            QMessageBox.warning(self, "警告", "请输入目标地址")
            return

        # 移除 http:// 和 https://
        target = remove_http_https(target)

        # 处理不同的 ping 类型
        if ping_type == "ICMP":
            if ':' in target:  # 如果包含端口，去除端口
                target = target.split(':')[0]
            if not (is_valid_ipv4(target) or is_valid_domain(target)):
                QMessageBox.warning(self, "警告", "请输入有效的 IP 地址、域名或计算机名")
                return
        elif ping_type == "TCP":
            if ':' not in target:
                QMessageBox.information(self, "提示", "未指定端口，将使用默认端口 80")
                target += ":80"
        elif ping_type in ["HTTP", "HTTPS"]:
            if ':' in target:
                target = target.split(':')[0]
        elif ping_type == "JavaMC":
            if ':' not in target:
                target += ":25565"
        elif ping_type == "BedrockMC":
            if ':' not in target:
                target += ":19132"
        elif ping_type == "API":
            if ':' in target:
                target = target.split(':')[0]

        self.ping_result.clear()
        self.ping_result.append(f"正在 ping {target}...")

        if ping_type == "API":
            self.api_ping(target)
        else:
            self.ping_thread = PingThread(target, ping_type)
            self.ping_thread.update_signal.connect(self.update_ping_result)
            self.ping_thread.start()

    def api_ping(self, target):
        try:
            url = f"https://uapis.cn/api/ping?host={target}"
            response = requests.get(url)
            data = response.json()
            if data['code'] == 200:
                self.ping_result.append(f"API Ping 结果:")
                self.ping_result.append(f"目标: {data['host']} (IP: {data['ip']})")
                self.ping_result.append(f"位置: {data['location']}")
                self.ping_result.append(f"最大延迟: {data['max']} ms")
                self.ping_result.append(f"平均延迟: {data['avg']} ms")
                self.ping_result.append(f"最小延迟: {data['min']} ms")
            else:
                self.ping_result.append(f"API Ping 失败: {data.get('msg', '未知错误')}")
        except Exception as e:
            self.ping_result.append(f"API Ping 错误: {str(e)}")

    def clean_minecraft_text(self, text):
        if not isinstance(text, str):
            return str(text)

        # 移除所有格式代码（格式为 §x，其中x可以是任意字符）
        import re
        cleaned_text = re.sub('§[0-9a-fk-or]', '', text)
        return cleaned_text

    def update_ping_result(self, target, result):
        try:
            if isinstance(result, dict):
                self.ping_result.append(f"Ping {target} 结果:")

                # 处理 Minecraft 服务器响应
                if '延迟' in result:
                    self.ping_result.append(f"延迟: {result['延迟']:.2f} ms")
                    if '版本' in result:
                        self.ping_result.append(f"版本: {self.clean_minecraft_text(result['版本'])}")
                    if '协议' in result:
                        self.ping_result.append(f"协议版本: {result['协议']}")
                    if '在线玩家' in result:
                        self.ping_result.append(f"在线玩家: {result['在线玩家']}")
                    if '最大玩家' in result:
                        self.ping_result.append(f"最大玩家数: {result['最大玩家']}")
                    if '描述' in result:
                        self.ping_result.append(f"服务器描述: {self.clean_minecraft_text(result['描述'])}")
                    if '游戏模式' in result:
                        self.ping_result.append(f"游戏模式: {self.clean_minecraft_text(result['游戏模式'])}")
                    if '地图' in result:
                        self.ping_result.append(f"地图: {self.clean_minecraft_text(result['地图'])}")
                else:
                    # 常规 ping 统计
                    if 'min' in result:
                        self.ping_result.append(f"最小延迟: {result['min']:.2f} ms")
                    if 'max' in result:
                        self.ping_result.append(f"最大延迟: {result['max']:.2f} ms")
                    if 'avg' in result:
                        self.ping_result.append(f"平均延迟: {result['avg']:.2f} ms")
                    if 'loss' in result:
                        self.ping_result.append(f"丢包率: {result['loss']}%")

            elif isinstance(result, (int, float)):
                self.ping_result.append(f"Ping {target}: {result:.2f} ms")

            else:
                self.ping_result.append(f"Ping {target}: {str(result)}")

        except Exception as e:
            self.ping_result.append(f"处理 Ping {target} 结果时出错: {str(e)}")
            self.logger.error(f"处理 ping 结果时出错: {str(e)}")

    def auto_update(self):
        """自动更新函数"""
        if self.token:
            self.load_nodes()

    def update_log(self, message):
        """更新日志显示"""
        self.log_display.append(message)
        self.log_display.verticalScrollBar().setValue(self.log_display.verticalScrollBar().maximum())

    def check_and_download_files(self):
        """检查并下载所需文件"""
        thread = threading.Thread(target=self._download_files)
        thread.start()

    def _download_files(self):
        required_files = [
            get_absolute_path('frpc.exe'),
        ]
        missing_files = [file for file in required_files if not os.path.exists(file)]

        if missing_files:
            self.logger.info("正在下载所需文件...")
            url = "https://www.chmlfrp.cn/dw/ChmlFrp-0.51.2_240715_windows_amd64.zip"
            try:
                response = requests.get(url, stream=True)
                response.raise_for_status()  # 检查是否成功获取
                zip_path = get_absolute_path("ChmlFrp.zip")
                with open(zip_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                extracted_folder = None
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    for file in zip_ref.namelist():
                        if file.endswith('frpc.exe'):
                            extracted_folder = file.split('/')[0]
                            zip_ref.extract(file)

                if extracted_folder:
                    src = os.path.join(extracted_folder, 'frpc.exe')
                    dst = get_absolute_path('frpc.exe')
                    if os.path.exists(src):
                        if os.path.exists(dst):
                            os.remove(dst)  # 如果文件已存在，先删除
                        shutil.move(src, dst)
                        self.logger.info("成功移动文件: frpc.exe")

                    # 清理解压出来的文件夹
                    shutil.rmtree(extracted_folder)
                    self.logger.info(f"已删除解压文件夹: {extracted_folder}")

                # 删除下载的zip文件
                os.remove(zip_path)

                self.logger.info("文件下载、提取和清理完成")
            except Exception as e:
                self.logger.error(f"下载或处理文件时发生错误: {str(e)}")


    def mousePressEvent(self, event):
        """鼠标按下事件"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = True
            self.offset = event.position().toPoint()

    def mouseMoveEvent(self, event):
        """鼠标移动事件"""
        try:
            if self.dragging:
                global_pos = event.globalPosition().toPoint()
                self.move(global_pos - self.offset)
        except Exception as e:
            self.logger.error(f"移动窗口时发生错误: {str(e)}")
            self.dragging = False

    def mouseReleaseEvent(self, event):
        """鼠标释放事件"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = False

    def closeEvent(self, event):
        # 停止所有运行中的隧道
        with QMutexLocker(self.running_tunnels_mutex):
            tunnels_to_stop = list(self.running_tunnels.keys())

        for tunnel_name in tunnels_to_stop:
            self.stop_single_tunnel(tunnel_name)

        # 停止所有普通隧道
        for tunnel_name, process in self.tunnel_processes.items():
            try:
                self.node_check_timer.stop()
                process.terminate()
                process.wait(timeout=5)
                if process.poll() is None:
                    process.kill()
            except Exception as e:
                self.logger.error(f"停止隧道 '{tunnel_name}' 时发生错误: {str(e)}")

        # 强制杀死当前目录下的 frpc.exe 进程
        try:
            self.forcefully_terminate_frpc()
        except Exception as e:
            self.logger.error(f"终止 frpc.exe 进程时发生错误: {str(e)}")

        # 调用原有的清理逻辑
        time.sleep(1)

        super().closeEvent(event)

    def forcefully_terminate_frpc(self):
        self.logger.info("正在终止当前目录下的 frpc.exe 进程...")
        current_directory = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本目录
        frpc_path = os.path.join(current_directory, 'frpc.exe')  # 当前目录下的 frpc.exe 完整路径

        # 检查 frpc.exe 是否存在
        if not os.path.exists(frpc_path):
            self.logger.error(f"{frpc_path} 不存在")
            return False

        # 封装进程终止逻辑
        def terminate_process(proc):
            try:
                self.logger.info(f"正在终止进程: {proc.info['pid']} - {frpc_path}")
                proc.terminate()  # 终止进程
                proc.wait()  # 等待进程完全结束
                self.logger.info(f"进程 {proc.info['pid']} 已终止")
            except psutil.NoSuchProcess:
                self.logger.error(f"进程 {proc.info['pid']} 已不存在")
            except psutil.AccessDenied:
                self.logger.error(f"访问被拒绝，无法终止进程 {proc.info['pid']}")
            except Exception as e:
                self.logger.error(f"终止进程 {proc.info['pid']} 时发生错误: {str(e)}")

        try:
            # psutil 获取所有进程
            for proc in psutil.process_iter(['pid', 'exe']):
                # 检查进程路径是否与指定路径匹配
                if proc.info['exe'] and os.path.normpath(proc.info['exe']) == os.path.normpath(frpc_path):
                    terminate_process(proc)  # 调用封装的终止进程函数

            self.logger.info("所有匹配的 frpc.exe 进程已终止")
            return True
        except psutil.NoSuchProcess:
            self.logger.error("未找到指定的 frpc.exe 进程")
            return False
        except psutil.AccessDenied:
            self.logger.error("访问被拒绝。您可能需要以管理员身份运行")
            return False
        except Exception as e:
            self.logger.error(f"终止 frpc.exe 进程时发生错误: {str(e)}")
            return False

    def cleanup(self):
        # 停止所有普通隧道
        for tunnel_name, process in list(self.tunnel_processes.items()):
            self.stop_tunnel({"name": tunnel_name})

        # 强制终止所有 frpc 进程
        self.forcefully_terminate_frpc()

        time.sleep(1)

        # 等待所有线程结束
        QThreadPool.globalInstance().waitForDone()

    def is_system_dark_theme(self):
        if sys.platform == "win32":
            try:
                registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
                key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return value == 0
            except:
                return False
        elif sys.platform == "darwin":
            try:
                result = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'], capture_output=True,
                                        text=True)
                return result.stdout.strip() == "Dark"
            except:
                return False
        else:
            return False

    def toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self.apply_theme()

        # 更新当前选中的按钮样式
        current_index = self.content_stack.currentIndex()
        if current_index < len(self.tab_buttons):
            self.update_button_styles(self.tab_buttons[current_index])


    def apply_theme(self):
        if self.dark_theme:
            self.button_color = "#0D47A1"
            self.button_hover_color = "#1565C0"
            self.setStyleSheet("""
				QWidget {
					color: #FFFFFF;
					background-color: #2D2D2D;
				}
				#background {
					background-color: #1E1E1E;
					border-radius: 10px;
				}
				QPushButton {
					background-color: #0D47A1;
					color: white;
					border: none;
					padding: 5px 10px;
					text-align: center;
					text-decoration: none;
					font-size: 14px;
					margin: 4px 2px;
					border-radius: 4px;
				}
				QPushButton:hover {
					background-color: #1565C0;
				}
				QPushButton:disabled {
					background-color: #424242;
				}
				QLineEdit, QComboBox, QTextEdit {
					padding: 5px;
					border: 1px solid #424242;
					border-radius: 4px;
					background-color: #1E1E1E;
					color: #FFFFFF;
				}
				NodeCard, TunnelCard, DomainCard {
					background-color: #2D2D2D;
					border: 1px solid #424242;
				}
				NodeCard:hover, TunnelCard:hover, DomainCard:hover {
					background-color: #3D3D3D;
				}
			""")
        else:
            self.button_color = "#4CAF50"
            self.button_hover_color = "#45a049"
            self.setStyleSheet("""
				QWidget {
					color: #333333;
					background-color: #FFFFFF;
				}
				#background {
					background-color: #F0F0F0;
					border-radius: 10px;
				}
				QPushButton {
					background-color: #4CAF50;
					color: white;
					border: none;
					padding: 5px 10px;
					text-align: center;
					text-decoration: none;
					font-size: 14px;
					margin: 4px 2px;
					border-radius: 4px;
				}
				QPushButton:hover {
					background-color: #45a049;
				}
				QPushButton:disabled {
					background-color: #CCCCCC;
				}
				QLineEdit, QComboBox, QTextEdit {
					padding: 5px;
					border: 1px solid #DCDCDC;
					border-radius: 4px;
					background-color: #F0F0F0;
					color: #333333;
				}
				NodeCard, TunnelCard, DomainCard {
					background-color: #FFFFFF;
					border: 1px solid #D0D0D0;
				}
				NodeCard:hover, TunnelCard:hover, DomainCard:hover {
					background-color: #F0F0F0;
				}
			""")
        if self.dark_theme:
            refresh_button_style = """
					QPushButton#refreshButton {
						background-color: #1E90FF;
						color: white;
						border: none;
						padding: 5px 10px;
						border-radius: 4px;
						font-weight: bold;
					}
					QPushButton#refreshButton:hover {
						background-color: #4169E1;
					}
				"""
        else:
            refresh_button_style = """
					QPushButton#refreshButton {
						background-color: #4CAF50;
						color: white;
						border: none;
						padding: 5px 10px;
						border-radius: 4px;
						font-weight: bold;
					}
					QPushButton#refreshButton:hover {
						background-color: #45a049;
					}
				"""

        self.setStyleSheet(self.styleSheet() + refresh_button_style)

    def refresh_nodes(self):
        """刷新节点状态"""
        self.load_nodes()
        self.logger.info("节点状态已刷新")

    def toggle_ddns(self):
        if not self.ddns_active:
            selected_domain = self.ddns_domain_combo.currentText()
            if selected_domain == "选择域名":
                QMessageBox.warning(self, "警告", "请选择一个域名")
                return
            self.start_ddns(selected_domain)
        else:
            self.stop_ddns()

    def stop_ddns(self):
        self.ddns_active = False
        self.ddns_status_label.setText("DDNS状态: 正在停止...")
        self.ddns_start_button.setEnabled(False)

        # 使用 QTimer 来延迟更新 UI，给线程一些时间来结束
        QTimer.singleShot(1000, self.finalize_ddns_stop)

    def finalize_ddns_stop(self):
        if self.ddns_thread and self.ddns_thread.is_alive():
            self.ddns_thread.join(timeout=0.1)

        self.ddns_status_label.setText("DDNS状态: 已停止")
        self.ddns_start_button.setText("启动DDNS")
        self.ddns_start_button.setEnabled(True)
        self.logger.info("DDNS 服务已停止")

    def load_user_domains(self):
        if self.token:
            try:
                url = f"http://cf-v2.uapis.cn/get_user_free_subdomains?token={self.token}"
                response = requests.get(url)
                if response.status_code == 200:
                    domains = response.json().get('data', [])
                    self.ddns_domain_combo.clear()
                    self.ddns_domain_combo.addItem("选择域名")
                    for domain in domains:
                        full_domain = f"{domain['record']}.{domain['domain']}"
                        self.ddns_domain_combo.addItem(full_domain)
                else:
                    self.logger.error("获取用户域名失败")
            except Exception as e:
                self.logger.error(f"加载用户域名时发生错误: {str(e)}")

    def switch_tab(self, tab_name):
        if tab_name == "user_info":
            self.content_stack.setCurrentIndex(0)
        elif tab_name == "tunnel":
            self.content_stack.setCurrentIndex(1)
        elif tab_name == "domain":
            self.content_stack.setCurrentIndex(2)
        elif tab_name == "node":
            self.content_stack.setCurrentIndex(3)
        elif tab_name == "ddns":
            self.content_stack.setCurrentIndex(4)
        elif tab_name == "ping":
            self.content_stack.setCurrentIndex(5)
        elif tab_name == "ip_tools":
            self.content_stack.setCurrentIndex(6)

        for button in self.tab_buttons:
            if button.text().lower().replace(" ", "_") == tab_name:
                self.update_button_styles(button)




    def stop_single_tunnel(self, tunnel_name):
        with QMutexLocker(self.running_tunnels_mutex):
            if tunnel_name in self.running_tunnels:
                worker = self.running_tunnels[tunnel_name]
                worker.requestInterruption()  # 请求中断
                if not worker.wait(5000):  # 等待最多5秒
                    worker.terminate()
                    worker.wait(2000)
                del self.running_tunnels[tunnel_name]
                self.logger.info(f"隧道 '{tunnel_name}' 已停止")
            else:
                self.logger.warning(f"尝试停止不存在的隧道: {tunnel_name}")

    def stop_all_tunnels(self):
        self.stop_worker = StopWorker(self.running_tunnels, self.tunnel_processes, self.logger)
        self.stop_thread = QThread()
        self.stop_worker.moveToThread(self.stop_thread)
        self.stop_thread.started.connect(self.stop_worker.run)
        self.stop_worker.finished.connect(self.stop_thread.quit)
        self.stop_worker.finished.connect(self.stop_worker.deleteLater)
        self.stop_thread.finished.connect(self.stop_thread.deleteLater)
        self.stop_thread.start()

    def update_tunnel_ui(self):
        for i in range(self.tunnel_container.layout().count()):
            widget = self.tunnel_container.layout().itemAt(i).widget()
            if isinstance(widget, TunnelCard):
                widget.is_running = widget.tunnel_info['name'] in self.tunnel_processes
                widget.update_status()


class NodeCard(QFrame):
    clicked = pyqtSignal(object)
    def __init__(self, node_info):
        super().__init__()
        self.node_info = node_info
        self.initUI()
        self.updateStyle()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        name_label = QLabel(f"<b>{self.node_info.get('node_name', 'N/A')}</b>")
        name_label.setObjectName("nameLabel")
        group_label = QLabel(f"节点组: {self.node_info.get('nodegroup', 'N/A')}")
        cpu_label = QLabel(f"CPU使用率: {self.node_info.get('cpu_usage', 'N/A')}%")
        bandwidth_label = QLabel(f"带宽使用率: {self.node_info.get('bandwidth_usage_percent', 'N/A')}%")

        layout.addWidget(name_label)
        layout.addWidget(group_label)
        layout.addWidget(cpu_label)
        layout.addWidget(bandwidth_label)

        self.setLayout(layout)
        self.setFixedSize(250, 150)

    def updateStyle(self):
        self.setStyleSheet("""
			NodeCard {
				border: 1px solid #d0d0d0;
				border-radius: 5px;
				padding: 10px;
				margin: 5px;
			}
			NodeCard:hover {
				background-color: rgba(240, 240, 240, 50);
			}
			#nameLabel {
				font-size: 16px;
				font-weight: bold;
			}
		""")

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self.node_info.get('state') == 'online':
            color = QColor(0, 255, 0)  # 绿色
        else:
            color = QColor(255, 0, 0)  # 红色
        painter.setPen(QPen(color, 2))
        painter.setBrush(color)
        painter.drawEllipse(self.width() - 20, 10, 10, 10)

    def setSelected(self, selected):
        if selected:
            self.setStyleSheet(
                self.styleSheet() + "NodeCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }")
        else:
            self.setStyleSheet(self.styleSheet().replace(
                "NodeCard { border: 2px solid #0066cc; background-color: rgba(224, 224, 224, 50); }", ""))

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.node_info)
        super().mousePressEvent(event)


if __name__ == '__main__':
    def exception_hook(exctype, value, traceback):
        while traceback:
            traceback = traceback.tb_next
        sys.__excepthook__(exctype, value, traceback)
    sys.excepthook = exception_hook
    try:
        app = QApplication(sys.argv)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"发生意外错误: {e}")
        traceback.print_exc()