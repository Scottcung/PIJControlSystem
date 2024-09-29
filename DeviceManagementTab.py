import socket
import logging
import binascii
import threading
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFrame, QInputDialog, QMessageBox
)

# 确保 utils.py 在同一目录下
from utils import is_valid_ip

PORT = 10086  # 默认通信端口

class DeviceManagementTab(QWidget):
    def __init__(self, translations, operation_log_tab):
        super().__init__()
        self.translations = translations
        self.operation_log_tab = operation_log_tab
        self.tab_name = "device_management"
        self.device_threads = []
        self.init_ui()

    def init_ui(self):
        if self.layout() is None:  # 检查是否已有布局
            self.layout = QVBoxLayout(self)

        # 创建一个水平布局，将 IP 标签、输入框和按钮放置在一起
        ip_layout = QHBoxLayout()

        # 添加 IP 地址标签和输入框
        self.ip_label = QLabel(self.translations.get('device_ip_label', '设备 IP 地址'))
        self.ip_input = QLineEdit()
        ip_layout.addWidget(self.ip_label)
        ip_layout.addWidget(self.ip_input)

        # 添加 "添加设备" 按钮
        self.add_device_button = QPushButton(self.translations.get('add_device_button', '添加设备'))
        self.add_device_button.clicked.connect(self.add_device)
        ip_layout.addWidget(self.add_device_button)

        # 将水平布局添加到主布局中
        self.layout.addLayout(ip_layout)

        # 设置添加设备区域布局
        self.layout.addStretch()  # 使按钮和设备列表靠上
        self.device_list_layout = QVBoxLayout()
        self.layout.addLayout(self.device_list_layout)
    
    def update_ui_texts(self):
        """更新UI文本"""
        self.ip_label.setText(self.translations.get('device_ip_label', '设备 IP 地址'))
        self.add_device_button.setText(self.translations.get('add_device_button', '添加设备'))
        
        # 更新每个设备框架的文本
        for i in range(self.device_list_layout.count()):
            frame = self.device_list_layout.itemAt(i).widget()
            if isinstance(frame, QFrame):
                labels = frame.findChildren(QLabel)
                # 更新设备名称
                device_name = labels[0].text().replace("Device Name: ", "")
                labels[0].setText(f"Device Name: {device_name}")
                # 更新 IP 地址
                ip_address = labels[1].text().replace("IP Addr.: ", "")
                labels[1].setText(f"IP Addr.: {ip_address}")

    def add_device_frame(self, device_name, ip_address, online_status="offline", print_count=0):
        """添加设备的框架"""
        frame = QFrame()
        frame.setFrameShape(QFrame.Box)
        frame_layout = QHBoxLayout()

        # 左侧显示设备信息
        info_layout = QVBoxLayout()

        # 添加设备名称标签，并允许双击修改设备名称
        label_device_name = QLabel(f"Device Name: {device_name}")
        label_device_name.mouseDoubleClickEvent = lambda event: self.change_device_name(label_device_name)

        label_ip_address = QLabel(f"IP Addr.: {ip_address}")
        label_online_status = QLabel(f"Status: {online_status}")
        label_print_count = QLabel(f"Finished Counts: {print_count}")
        info_layout.addWidget(label_device_name)
        info_layout.addWidget(label_ip_address)
        info_layout.addWidget(label_online_status)
        info_layout.addWidget(label_print_count)

        # 右侧按钮
        button_layout = QVBoxLayout()
        start_button = QPushButton("Start")
        stop_button = QPushButton("Stop")
        delete_button = QPushButton("Delete")
        button_layout.addWidget(start_button)
        button_layout.addWidget(stop_button)
        button_layout.addWidget(delete_button)
        
        # 绑定按钮的点击事件
        start_button.clicked.connect(lambda: self.handle_start_command(ip_address))
        stop_button.clicked.connect(lambda: self.handle_stop_command(ip_address))
        delete_button.clicked.connect(lambda: self.remove_device_frame(frame))

        # 将信息和按钮布局添加到 Frame 中
        frame_layout.addLayout(info_layout)
        frame_layout.addLayout(button_layout)
        frame.setLayout(frame_layout)

        # 将设备 Frame 添加到设备列表中
        self.device_list_layout.addWidget(frame)

    def remove_device_frame(self, frame):
        """删除设备的框架"""
        frame.deleteLater()

    def change_device_name(self, label):
        """弹出输入框，修改设备名称"""
        current_name = label.text().replace("Device Name: ", "")
        new_name, ok = QInputDialog.getText(self, "修改设备名称", "请输入新的设备名称:", text=current_name)

        if ok and new_name:
            if self.is_device_name_unique(new_name):
                label.setText(f"Device Name: {new_name}")
            else:
                QMessageBox.warning(self, self.translations['error'], "设备名称已存在，请重新输入")

    def is_device_name_unique(self, name):
        """检查设备名称是否唯一"""
        for widget in self.device_list_layout.children():
            if isinstance(widget, QFrame):
                device_name_label = widget.findChildren(QLabel)[0]
                if device_name_label.text().replace("Device Name: ", "") == name:
                    return False
        return True

    def start_finished_counts_thread(self):
            """启动线程，每秒向所有设备发送 finished counts 指令"""
            thread = threading.Thread(target=self.finished_counts_loop)
            thread.daemon = True  # 设置为守护线程
            thread.start()
            self.device_threads.append(thread)

    def finished_counts_loop(self):
        while True:
            device_list = self.get_device_list()
            for device_name, ip_address in device_list:
                try:
                    # 尝试发送命令并更新状态为 online
                    self.send_finished_counts_command(ip_address)
                    
                    # 更新状态为 online
                    for i in range(self.device_list_layout.count()):
                        frame = self.device_list_layout.itemAt(i).widget()
                        if isinstance(frame, QFrame):
                            labels = frame.findChildren(QLabel)
                            if labels[1].text().replace("IP Addr.: ", "") == ip_address:
                                labels[2].setText("Status: online")  # 更新状态标签
                                
                except Exception as e:
                    # 更新设备状态为 offline
                    for i in range(self.device_list_layout.count()):
                        frame = self.device_list_layout.itemAt(i).widget()
                        if isinstance(frame, QFrame):
                            labels = frame.findChildren(QLabel)
                            if labels[1].text().replace("IP Addr.: ", "") == ip_address:
                                labels[2].setText("Status: offline")  # 更新状态标签
                    logging.error(f"Error communicating with {ip_address}: {e}")

            time.sleep(1)  # 每秒发送一次

    def send_finished_counts_command(self, ip_address):
        if not hasattr(self, 'packet_number'):
            self.packet_number = 0

        # Construct the finished counts command packet
        packet = self.build_finishedcounts_command_packet(self.packet_number)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((ip_address, PORT))
                s.sendall(packet)

                # Log the sent command packet in hexadecimal format
                hex_packet = binascii.hexlify(packet).decode('utf-8')
                self.operation_log_tab.add_log_message(f"Sent finished counts command to {ip_address}: {hex_packet}")

                # Receive the response packet
                response = s.recv(1024)
                self.handle_finished_counts_response(response, ip_address)

        except Exception as e:
            error_message = f"Failed to send finished counts command to {ip_address}: {e}"
            self.operation_log_tab.add_log_message(error_message)
            logging.error(error_message)

        self.packet_number = (self.packet_number + 1) % 256

    def handle_finished_counts_response(self, response_packet, ip_address):
        # 分割接收到的原始数据包
        packets = self.split_packets(response_packet)
        
        for packet in packets:
            raw_packet = ' '.join(f'{byte:02X}' for byte in packet)
            self.operation_log_tab.add_log_message(f"Received raw packet from {ip_address}: {raw_packet}")

            if packet[:2] != bytes([0x69, 0xAA]):
                self.operation_log_tab.add_log_message("Invalid packet header")
                continue

            # 检查包类型是否为 0x04
            if packet[4] != 0x04:
                self.operation_log_tab.add_log_message("Invalid packet type")
                continue

            # 获取并打印用于转换的字节
            finished_counts_bytes = packet[8:11]
            self.operation_log_tab.add_log_message(f"Extracted bytes for finished counts: {finished_counts_bytes.hex()}")

            # 进行转换
            finished_counts = int.from_bytes(finished_counts_bytes, byteorder='big')

            # 更新设备的 finished counts 标签
            for i in range(self.device_list_layout.count()):
                frame = self.device_list_layout.itemAt(i).widget()
                if isinstance(frame, QFrame):
                    labels = frame.findChildren(QLabel)
                    label_print_count = labels[3]  # 找到 Finished Counts 标签
                    label_print_count.setText(f"Finished Counts: {finished_counts}")

            # 记录打印完成个数到操作日志
            self.operation_log_tab.add_log_message(f"Finished Counts for {ip_address}: {finished_counts} (Decimal: {finished_counts})")
                
    def add_device(self):
        ip_address = self.ip_input.text()

        if not ip_address or not is_valid_ip(ip_address):
            QMessageBox.warning(self, self.translations['error'], self.translations['ip_error'])
            return

        online_status = "online" if self.check_device_online(ip_address, PORT) else "offline"
        device_name = f"Device {len(self.device_list_layout.children()) + 1}"
        self.add_device_frame(device_name, ip_address, online_status, print_count=0)

        # 启动 finished counts 线程
        self.start_finished_counts_thread()

    def check_device_online(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((ip, port))
                return True
        except (socket.timeout, socket.error) as e:
            logging.error(f"Connection error: {e}")
            return False

    def get_device_list(self):
        device_list = []
        for i in range(self.device_list_layout.count()):
            frame = self.device_list_layout.itemAt(i).widget()
            if isinstance(frame, QFrame):
                labels = frame.findChildren(QLabel)
                device_name = labels[0].text().replace("Device Name: ", "")
                ip_address = labels[1].text().replace("IP Addr.: ", "")
                device_list.append((device_name, ip_address))
        return device_list

    def build_start_command_packet(self, packet_number):
        # 包头 0x69, 0xAA
        header = bytes([0x69, 0xAA])

        # 包类型 0x01
        packet_type = bytes([0x01])

        # 包号 (0-255 循环累加)
        packet_num = bytes([packet_number])

        # 功能码 0x83
        function_code = bytes([0x83])

        # 参数地址 0x00, 0x03
        param_address = bytes([0x00, 0x03])

        # 参数内容 0x00, 0x01 (启动指令)
        param_content = bytes([0x00, 0x01])

        # 包尾 0x0A, 0x0D
        tail = bytes([0x0A, 0x0D])

        # 包长度 (从包类型到包尾的长度), 包含：包类型、包号、功能码、参数地址、参数内容、包尾
        # 包类型到包尾的字节数共 9 字节
        packet_length = len(packet_type + packet_num + function_code + param_address + param_content + tail)
        
        # 包长度要填充到 2 个字节，因此分为高位和低位
        length_bytes = bytes([packet_length >> 8, packet_length & 0xFF])

        # 组装整个包
        packet = header + length_bytes + packet_type + packet_num + function_code + param_address + param_content + tail

        return packet
    
    def build_stop_command_packet(self, packet_number):
        # 包头 0x69, 0xAA
        header = bytes([0x69, 0xAA])

        # 包类型 0x01
        packet_type = bytes([0x01])

        # 包号 (0-255 循环累加)
        packet_num = bytes([packet_number])

        # 功能码 0x83
        function_code = bytes([0x83])

        # 参数地址 0x00, 0x04
        param_address = bytes([0x00, 0x04])

        # 参数内容 0x00, 0x01 (启动指令)
        param_content = bytes([0x00, 0x01])

        # 包尾 0x0A, 0x0D
        tail = bytes([0x0A, 0x0D])

        # 包长度 (从包类型到包尾的长度), 包含：包类型、包号、功能码、参数地址、参数内容、包尾
        # 包类型到包尾的字节数共 9 字节
        packet_length = len(packet_type + packet_num + function_code + param_address + param_content + tail)
        
        # 包长度要填充到 2 个字节，因此分为高位和低位
        length_bytes = bytes([packet_length >> 8, packet_length & 0xFF])

        # 组装整个包
        packet = header + length_bytes + packet_type + packet_num + function_code + param_address + param_content + tail

        return packet
    
    def parse_response_packet(self, response_packet):
        # 打印接收到的原始数据包
        raw_packet = ' '.join(f'{byte:02X}' for byte in response_packet)
        self.operation_log_tab.add_log_message(f"Received raw packet (hex): {raw_packet}")
        
        # 判断包长度是否合法
        if len(response_packet) < 10:
            self.operation_log_tab.add_log_message("Invalid packet length")
            return False, "Invalid packet length"

        # 检查包头是否正确 (0x69, 0xAA)
        if response_packet[:2] != bytes([0x69, 0xAA]):
            self.operation_log_tab.add_log_message("Invalid packet header")
            return False, "Invalid packet header"

        # 提取包类型（第5个字节，索引为4）
        packet_type = response_packet[4]
        self.operation_log_tab.add_log_message(f"Extracted packet type: {packet_type:02X}")

        # 提取功能码（第7个字节，索引为6）
        function_code = response_packet[6]
        self.operation_log_tab.add_log_message(f"Extracted function code: {function_code:02X}")

        # 检查包类型是否为应答包 (0x02 或 0x03)
        if packet_type not in [0x02, 0x03]:
            self.operation_log_tab.add_log_message(f"Invalid packet type: {packet_type:02X}")
            return False, f"Invalid packet type: {packet_type:02X}"

        # 检查功能码是否正确 (0x83)
        if function_code != 0x83:
            self.operation_log_tab.add_log_message(f"Invalid function code: {function_code:02X}")
            return False, f"Invalid function code: {function_code:02X}"

        # 检查结果类型（第8个字节，索引为7）
        result_type = response_packet[7]
        if result_type == 0x00:
            log_message = "Command executed successfully"
            self.operation_log_tab.add_log_message(log_message)
            return True, log_message
        else:
            log_message = f"Command execution failed with result type: {result_type:02X}"
            self.operation_log_tab.add_log_message(log_message)
            return False, log_message

    def send_start_command(self, ip_address, packet_number):
        try:
            # 构建日志消息，记录指令发送的细节
            log_message = f"Sending start command to {ip_address} with packet number {packet_number}."

            # 创建 socket 连接
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((ip_address, PORT))
                
                # 构建启动命令包
                packet = self.build_start_command_packet(packet_number)

                # 将发送的指令转换为16进制字符串
                hex_packet = binascii.hexlify(packet).decode('utf-8')
                packet_log_message = f"Packet (hex): {hex_packet}"

                # 发送命令包
                s.sendall(packet)

                # 在发送指令后，将日志消息和16进制指令包添加到 operation_log_tab
                self.operation_log_tab.add_log_message(log_message)
                self.operation_log_tab.add_log_message(packet_log_message)
                
                # 接收应答包并处理粘包问题
                response = s.recv(1024)

                # 将接收到的数据转换为16进制字符串
                hex_response = binascii.hexlify(response).decode('utf-8')
                self.operation_log_tab.add_log_message(f"Received raw packet (hex): {hex_response}")

                # 分离多个包并逐个解析
                packets = self.split_packets(response)

                # 记录所有收到的包
                for i, packet in enumerate(packets):
                    packet_hex = binascii.hexlify(packet).decode('utf-8')
                    # 解析每个包
                    success, message = self.parse_response_packet(packet)
                    # 记录每个包的16进制内容及其解析结果
                    response_log_message = f"Received packet {i+1} (hex): {packet_hex}, Parsed message: {message}"
                    self.operation_log_tab.add_log_message(response_log_message)

                # 返回第一个包的结果，或者根据逻辑处理返回多个包
                return success, message

        except Exception as e:
            # 记录错误消息到日志
            error_message = f"Error sending start command to {ip_address}: {e}"
            self.operation_log_tab.add_log_message(error_message)
            logging.error(error_message)
            return False, str(e)
        
    def send_stop_command(self, ip_address, packet_number):
        try:
            # 构建日志消息，记录指令发送的细节
            log_message = f"Sending stop command to {ip_address} with packet number {packet_number}."

            # 创建 socket 连接
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((ip_address, PORT))
                
                # 构建启动命令包
                packet = self.build_stop_command_packet(packet_number)

                # 将发送的指令转换为16进制字符串
                hex_packet = binascii.hexlify(packet).decode('utf-8')
                packet_log_message = f"Packet (hex): {hex_packet}"

                # 发送命令包
                s.sendall(packet)

                # 在发送指令后，将日志消息和16进制指令包添加到 operation_log_tab
                self.operation_log_tab.add_log_message(log_message)
                self.operation_log_tab.add_log_message(packet_log_message)
                
                # 接收应答包并处理粘包问题
                response = s.recv(1024)

                # 将接收到的数据转换为16进制字符串
                hex_response = binascii.hexlify(response).decode('utf-8')
                self.operation_log_tab.add_log_message(f"Received raw packet (hex): {hex_response}")

                # 分离多个包并逐个解析
                packets = self.split_packets(response)

                # 记录所有收到的包
                for i, packet in enumerate(packets):
                    packet_hex = binascii.hexlify(packet).decode('utf-8')
                    # 解析每个包
                    success, message = self.parse_response_packet(packet)
                    # 记录每个包的16进制内容及其解析结果
                    response_log_message = f"Received packet {i+1} (hex): {packet_hex}, Parsed message: {message}"
                    self.operation_log_tab.add_log_message(response_log_message)

                # 返回第一个包的结果，或者根据逻辑处理返回多个包
                return success, message

        except Exception as e:
            # 记录错误消息到日志
            error_message = f"Error sending stop command to {ip_address}: {e}"
            self.operation_log_tab.add_log_message(error_message)
            logging.error(error_message)
            return False, str(e)

    def split_packets(self, response_data):
        """
        根据包的头部 (0x69 0xAA) 和尾部 (0x0A 0x0D) 分离多个粘在一起的包。
        """
        packets = []
        start = 0
        while start < len(response_data):
            # 查找包头 '0x69 0xAA'
            start_index = response_data.find(b'\x69\xAA', start)
            if start_index == -1:
                break  # 没有找到更多包

            # 查找包尾 '0x0A 0x0D'
            end_index = response_data.find(b'\x0A\x0D', start_index)
            if end_index == -1:
                break  # 没有找到包尾

            # 完整的包：从包头到包尾（包含包尾的两个字节）
            packet = response_data[start_index:end_index + 2]
            packets.append(packet)

            # 更新开始位置，寻找下一个包
            start = end_index + 2

        return packets

    def handle_start_command(self, ip_address):
        # 维护一个包号的状态，每次发送时累加
        if not hasattr(self, 'packet_number'):
            self.packet_number = 0
        
        # 发送启动命令
        success, message = self.send_start_command(ip_address, self.packet_number)
        
        # 包号递增
        self.packet_number = (self.packet_number + 1) % 256
        
        # 显示结果
        if success:
            QMessageBox.information(self, "Success", message)
            if hasattr(self, 'operation_log_tab'):
                self.operation_log_tab.add_log_message(f"Printer {ip_address} Start Sucessfully: {message}")
        else:
            QMessageBox.warning(self, "Error", message)
            if hasattr(self, 'operation_log_tab'):
                self.operation_log_tab.add_log_message(f"Printer {ip_address} Start Failed: {message}")
    
    def handle_stop_command(self, ip_address):
        # 维护一个包号的状态，每次发送时累加
        if not hasattr(self, 'packet_number'):
            self.packet_number = 0
        
        # 发送启动命令
        success, message = self.send_stop_command(ip_address, self.packet_number)
        
        # 包号递增
        self.packet_number = (self.packet_number + 1) % 256
        
        # 显示结果
        if success:
            QMessageBox.information(self, "Success", message)
            if hasattr(self, 'operation_log_tab'):
                self.operation_log_tab.add_log_message(f"Printer {ip_address} Stop Sucessfully: {message}")
        else:
            QMessageBox.warning(self, "Error", message)
            if hasattr(self, 'operation_log_tab'):
                self.operation_log_tab.add_log_message(f"Printer {ip_address} Stop Failed: {message}")

    def build_finishedcounts_command_packet(self, packet_number):
        # 包头 0x69, 0xAA
        header = bytes([0x69, 0xAA])

        # 包类型 0x01
        packet_type = bytes([0x01])

        # 包号 (0-255 循环累加)
        packet_num = bytes([packet_number])

        # 功能码 0x68
        function_code = bytes([0x68])

        # 包尾 0x0A, 0x0D
        tail = bytes([0x0A, 0x0D])

        # 包长度 (从包类型到包尾的长度), 包含：包类型、包号、功能码、包尾
        # 包类型到包尾的字节数共 9 字节
        packet_length = len(packet_type + packet_num + function_code + tail)
        
        # 包长度要填充到 2 个字节，因此分为高位和低位
        length_bytes = bytes([packet_length >> 8, packet_length & 0xFF])

        # 组装整个包
        packet = header + length_bytes + packet_type + packet_num + function_code + tail

        return packet
    