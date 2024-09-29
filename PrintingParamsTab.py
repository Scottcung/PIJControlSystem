from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton

class PrintingParamsTab(QWidget):
    def __init__(self, translations):
        super().__init__()
        self.translations = translations
        self.tab_name = "printing_params"  # 定义 tab_name 属性
        self.init_ui()

    def init_ui(self):
        if self.layout() is None:
            self.layout = QVBoxLayout(self)
        self.create_widgets()
    
    def create_widgets(self):
        self.param_label = QLabel(self.translations.get('printing_param_label', '打印参数'))
        self.param_input = QLineEdit()
        self.param_button = QPushButton(self.translations.get('apply_button', '应用'))
        
        for widget in [self.param_label, self.param_input, self.param_button]:
            self.layout.addWidget(widget)

    def update_ui_texts(self):
        """更新UI文本"""
        self.param_label.setText(self.translations.get('printing_param_label', '打印参数'))
        self.param_button.setText(self.translations.get('apply_button', '应用'))
