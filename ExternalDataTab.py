import socket
from PyQt5.QtWidgets import (QComboBox, QPushButton, QVBoxLayout, QDialog, QFormLayout, QLabel,
                             QLineEdit, QWidget, QHBoxLayout, QCheckBox, QMessageBox)

class ExternalDataTab(QWidget):
    def __init__(self, translations, device_management_tab, operation_log_tab):
        super().__init__()
        self.translations = translations
        self.device_management_tab = device_management_tab
        self.operation_log_tab = operation_log_tab
        self.tab_name = "external_data"
        self.labels = []
        self.checkboxes = []
        self.packet_number = 0
        self.init_ui()

    def init_ui(self):
        if not hasattr(self, 'main_layout') or self.main_layout is None:  # 检查是否已有布局
            self.main_layout = QVBoxLayout(self)

        # 设备选择和刷新按钮布局
        device_layout = QHBoxLayout()
        self.device_combobox = QComboBox()
        self.refresh_device_list()
        device_layout.addWidget(self.device_combobox)

        self.refresh_button = QPushButton(self.translations.get('refresh_button', "Refresh List"))
        self.refresh_button.clicked.connect(self.refresh_device_list)
        device_layout.addWidget(self.refresh_button)

        self.main_layout.addLayout(device_layout)

        # 标签操作按钮布局
        button_layout = QHBoxLayout()
        self.add_label_button = QPushButton(self.translations.get('add_label_button', "Add Label"))
        self.add_label_button.clicked.connect(self.open_input_dialog)
        button_layout.addWidget(self.add_label_button)

        self.send_label_button = QPushButton(self.translations.get('send_label_button', "Send Label"))
        self.send_label_button.clicked.connect(self.send_labels)
        button_layout.addWidget(self.send_label_button)

        self.main_layout.addLayout(button_layout)

        # 标签显示区域
        self.labels_layout = QVBoxLayout()
        self.main_layout.addLayout(self.labels_layout)
    
    def update_ui_texts(self):
        """更新UI文本"""
        self.refresh_button.setText(self.translations.get('refresh_button', "Refresh List"))
        self.add_label_button.setText(self.translations.get('add_label_button', "Add Label"))
        self.send_label_button.setText(self.translations.get('send_label_button', "Send Label"))

    def refresh_device_list(self):
        """刷新设备下拉框中的设备列表"""
        self.device_combobox.clear()  # 清空当前设备列表

        # 从 DeviceManagementTab 获取设备列表
        devices = self.device_management_tab.get_device_list()  # 设备名和IP地址的列表

        # 将设备名和IP地址添加到下拉框中
        for device_name, ip_address in devices:
            self.device_combobox.addItem(f"{device_name} ({ip_address})")

    def open_input_dialog(self):
        """打开标签输入对话框"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Input Label Content")

        form_layout = QFormLayout(dialog)
        mid_input = QLineEdit(dialog)
        sid_input = QLineEdit(dialog)
        val_input = QLineEdit(dialog)

        form_layout.addRow("MID (two nums):", mid_input)
        form_layout.addRow("SID (two nums):", sid_input)
        form_layout.addRow("VAL:", val_input)

        # 提交按钮
        submit_button = QPushButton("提交", dialog)
        submit_button.clicked.connect(lambda: self.add_label(mid_input.text(), sid_input.text(), val_input.text(), dialog))
        form_layout.addWidget(submit_button)

        dialog.setLayout(form_layout)
        dialog.exec_()

    def add_label(self, mid, sid, val, dialog):
        """添加标签到布局中"""
        if len(mid) != 2 or len(sid) != 2 or not val:
            QMessageBox.warning(self, "输入错误", "MID和SID必须是两位数字, VAL不能为空")
            return

        # 创建标签和复选框
        h_layout = QHBoxLayout()
        checkbox = QCheckBox()
        label_display = QLabel(f"MID: {mid}, SID: {sid}, VAL: {val}")

        # 保存标签信息和复选框
        self.labels.append((mid, sid, val))
        self.checkboxes.append(checkbox)

        # 创建删除按钮
        delete_button = QPushButton("Delete Label")
        delete_button.clicked.connect(lambda: self.remove_label(h_layout, checkbox))

        # 创建修改按钮
        edit_button = QPushButton("Edit Label")
        edit_button.clicked.connect(lambda: self.open_edit_dialog(mid, sid, val, label_display))

        # 添加控件到布局
        h_layout.addWidget(checkbox)
        h_layout.addWidget(label_display)
        h_layout.addWidget(edit_button)
        h_layout.addWidget(delete_button)
        self.labels_layout.addLayout(h_layout)

        dialog.accept()

    def open_edit_dialog(self, mid, sid, val, label_display):
        """打开标签编辑对话框"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Label Content")

        form_layout = QFormLayout(dialog)
        mid_input = QLineEdit(dialog)
        sid_input = QLineEdit(dialog)
        val_input = QLineEdit(dialog)

        mid_input.setText(mid)
        sid_input.setText(sid)
        val_input.setText(val)

        form_layout.addRow("MID (two nums):", mid_input)
        form_layout.addRow("SID (two nums):", sid_input)
        form_layout.addRow("VAL:", val_input)

        # 提交按钮
        submit_button = QPushButton("提交", dialog)
        submit_button.clicked.connect(lambda: self.update_label(mid_input.text(), sid_input.text(), val_input.text(), label_display, dialog))
        form_layout.addWidget(submit_button)

        dialog.setLayout(form_layout)
        dialog.exec_()

    def update_label(self, mid, sid, val, label_display, dialog):
        """更新标签内容"""
        if len(mid) != 2 or len(sid) != 2 or not val:
            QMessageBox.warning(self, "输入错误", "MID和SID必须是两位数字, VAL不能为空")
            return

        # 更新标签信息
        index = self.labels.index((label_display.text().split(", ")[0].split(": ")[1], label_display.text().split(", ")[1].split(": ")[1], label_display.text().split(", ")[2].split(": ")[1]))
        self.labels[index] = (mid, sid, val)
        label_display.setText(f"MID: {mid}, SID: {sid}, VAL: {val}")

        dialog.accept()

    def remove_label(self, layout, checkbox):
        """删除标签和对应的复选框"""
        index = self.checkboxes.index(checkbox)
        del self.labels[index]
        del self.checkboxes[index]

        # 删除布局中的控件
        for i in reversed(range(layout.count())): 
            widget = layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        self.labels_layout.removeItem(layout)

    def generate_packet(self):
        """生成数据包"""
        selected_labels = [(mid, sid, val) for (mid, sid, val), checkbox in zip(self.labels, self.checkboxes) if checkbox.isChecked()]
        
        if not selected_labels:
            QMessageBox.warning(self, "未选择标签", "请勾选要生成数据包的标签")
            return

        # 生成数据包
        data_packet = self.create_data_packet(selected_labels)
        
        # 显示生成的数据包
        QMessageBox.information(self, "数据包生成", f"生成的数据包: {data_packet}")

    def create_data_packet(self, selected_labels):
        """根据选择的标签生成数据包"""
        packet = []

        # 包头
        packet.append(0x69)  # 包头1
        packet.append(0xAA)  # 包头2

        # 包长度占位符，稍后计算
        packet.append(0x00)  # 包长度高位
        packet.append(0x00)  # 包长度低位

        # 包类型
        packet.append(0x01)  # 包类型 0x01

        # 包号
        packet.append(self.packet_number)  # 使用当前包号

        # 功能码
        packet.append(0x82)  # 功能码 0x82

        # 标签个数
        tag_count = len(selected_labels)
        packet.append(tag_count)

        # 循环生成标签数据
        for mid, sid, val in selected_labels:
            packet.append(int(mid))  # 标签主序号
            packet.append(int(sid))  # 标签子序号

            val_bytes = val.encode('utf-16-be')  # Unicode编码为字节序列
            byte_count = len(val_bytes)

            # 标签内容字节个数
            packet.append(byte_count >> 8)  # 高位字节
            packet.append(byte_count & 0xFF)  # 低位字节
            packet.extend(val_bytes)  # 标签内容

        # 计算包长度（从包类型开始到包尾）
        # 从包类型开始 (packet[4] 到包尾)
        data_section = packet[4:]  # 不包括包头和包长度字段
        packet_length = len(data_section) + 2  # 加上包尾的2个字节

        # 将包长度写入包的第3和第4个字节
        packet[2] = packet_length >> 8  # 长度高位
        packet[3] = packet_length & 0xFF  # 长度低位

        # 包尾
        packet.append(0x0A)  # 包尾1
        packet.append(0x0D)  # 包尾2

        return packet

    def increment_packet_number(self):
        """递增包号,并在0-255之间循环"""
        self.packet_number = (self.packet_number + 1) % 256

    def send_labels(self):
        """发送被勾选的标签内容"""
        selected_labels = [(mid, sid, val) for (mid, sid, val), checkbox in zip(self.labels, self.checkboxes) if checkbox.isChecked()]
        
        if not selected_labels:
            QMessageBox.warning(self, "未选择标签", "请勾选要发送的标签内容")
            return
        
        # 生成数据包
        data_packet = self.create_data_packet(selected_labels)
        hex_data_packet = ''.join(format(byte, '02X') for byte in data_packet)  # 转换为16进制字符串

        # 获取选中的设备的IP地址
        selected_device = self.device_combobox.currentText()
        ip_address = selected_device.split('(')[-1].strip(')')

        try:
            # 通过TCP/IP发送数据包
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((ip_address, 10086))  
                sock.sendall(bytearray(data_packet))

            log_message = f"发送数据包: {hex_data_packet} 到设备 {ip_address}"
            self.operation_log_tab.add_log_message(log_message)
        except Exception as e:
            QMessageBox.critical(self, "发送失败", f"发送数据包时发生错误: {e}")
            return

        QMessageBox.information(self, "发送成功", log_message)

        # 发送成功后递增包号
        self.increment_packet_number()

    def receive_packet(self, packet):
        """处理接收到的数据包，并验证包号是否匹配"""
        if len(packet) < 10:
            QMessageBox.warning(self, "接收错误", "接收到的数据包长度不足")
            return

        # 解析接收的数据包
        header = packet[:2]  # 包头
        packet_length = (packet[2] << 8) | packet[3]  # 包长度
        packet_type = packet[4]  # 包类型
        received_packet_number = packet[5]  # 包号
        function_code = packet[6]  # 功能码
        result_type = packet[7]  # 结果类型
        footer = packet[-2:]  # 包尾

        # 检查包头和包尾
        if header != [0x69, 0xAA] or footer != [0x0A, 0x0D]:
            QMessageBox.warning(self, "包格式错误", "接收到的数据包格式不正确")
            return

        if received_packet_number != self.packet_number:
            QMessageBox.warning(self, "包号不匹配", f"接收到的包号 {received_packet_number} 与发送的包号 {self.packet_number} 不一致")
            return

        # 结果处理
        if result_type == 0x00:
            result_message = "设置成功"
        elif result_type == 0x01:
            result_message = "设置失败"
        elif result_type == 0x02:
            result_message = "正在进行非外部模式喷印"
        else:
            result_message = "未知结果类型"

        log_message = f"接收数据包: {packet}, 结果: {result_message}"
        self.operation_log_tab.add_log_message(log_message)
        QMessageBox.information(self, "接收成功", log_message)

