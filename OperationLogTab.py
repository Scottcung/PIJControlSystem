from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QMessageBox
import os
from datetime import datetime

class OperationLogTab(QWidget):
    def __init__(self, translations):
        super().__init__()
        self.translations = translations
        self.tab_name = "operation_log"
        self.init_ui()

    def init_ui(self):
        if self.layout() is None:
            self.layout = QVBoxLayout(self)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)

        self.clear_log_button = QPushButton(self.translations.get('clear_log', '清除日志'))
        self.clear_log_button.clicked.connect(self.clear_log)

        self.download_log_button = QPushButton(self.translations.get('download_log', '下载日志'))
        self.download_log_button.clicked.connect(self.download_log)

        self.layout.addWidget(self.log_display)
        self.layout.addWidget(self.clear_log_button)
        self.layout.addWidget(self.download_log_button)

    def update_ui_texts(self):
        """更新UI文本"""
        ui_texts = {
            'clear_log': '清除日志',
            'download_log': '下载日志'
        }
        for key, text in ui_texts.items():
            getattr(self, f"{key}_button").setText(self.translations.get(key, text))

    def add_log_message(self, message):
        """向日志窗口添加日志消息，并添加日期和时间"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"  # 创建日志条目
        self.log_display.append(log_entry)  # 添加到日志显示窗口

    def clear_log(self):
        """清除日志窗口内容"""
        self.log_display.clear()

    def download_log(self):
        """下载日志到文本文件"""
        try:
            log_content = self.log_display.toPlainText()
            if not log_content:
                QMessageBox.warning(self, self.translations.get('warning', '警告'), self.translations.get('no_log_to_download', '没有日志可下载'))
                return
            
            file_path = os.path.join(os.getcwd(), "operation_log.txt")
            with open(file_path, 'w', encoding='utf-8') as log_file:
                log_file.write(log_content)

            log_message = self.translations.get('log_downloaded', '日志已下载到 operation_log.txt')
            QMessageBox.information(self, self.translations.get('success', '成功'), log_message)
        except Exception as e:
            QMessageBox.critical(self, self.translations.get('error', '错误'), str(e))
