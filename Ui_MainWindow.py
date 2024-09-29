import sys
import os
import pandas as pd
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget, QMenuBar, QAction, QFrame, QInputDialog, QApplication
)
from DeviceManagementTab import DeviceManagementTab  # 应该从 DeviceManagementTab.py 文件中导入
from PrintingParamsTab import PrintingParamsTab  # 应该从 PrintingParamsTab.py 文件中导入
from ExternalDataTab import ExternalDataTab  # 应该从 ExternalDataTab.py 文件中导入
from OperationLogTab import OperationLogTab  # 应该从 OperationLogTab.py 文件中导入

class Ui_MainWindow(QWidget):
    def __init__(self, lang='English'):
        super().__init__()

        self.lang = lang
        self.all_translations = self.load_all_translations("resources/translations.xlsx")
        self.translations = self.all_translations.get(self.lang, {})
        self.setWindowTitle(self.translations.get('device_management_system', '设备管理系统'))
        self.resize(800, 600)

        # 创建菜单栏
        self.menu_bar = QMenuBar(self)
        self.language_menu = self.menu_bar.addMenu(self.translations.get('language', '语言 (Language)'))

        # 创建菜单项：英文和中文
        self.action_english = QAction(self.translations.get('english', 'English'), self)
        self.action_chinese = QAction(self.translations.get('chinese', '中文'), self)

        # 将语言菜单项添加到语言菜单
        self.language_menu.addAction(self.action_english)
        self.language_menu.addAction(self.action_chinese)

        # 连接语言菜单项的点击事件
        self.action_english.triggered.connect(lambda: self.change_language('English'))
        self.action_chinese.triggered.connect(lambda: self.change_language('Chinese'))

        # 创建一个 Tab Widget
        self.tabs = QTabWidget()

        # 先创建 OperationLogTab，确保它可以传递给其他 Tab
        self.operation_log_tab = OperationLogTab(self.translations)

        # 将 OperationLogTab 传递给 DeviceManagementTab
        self.device_management_tab = DeviceManagementTab(self.translations, self.operation_log_tab)
        self.printing_params_tab = PrintingParamsTab(self.translations)

        # 将 OperationLogTab 也传递给 ExternalDataTab
        self.external_data_tab = ExternalDataTab(self.translations, self.device_management_tab, self.operation_log_tab)

        # 向分页添加内容
        self.tabs.addTab(self.device_management_tab, self.translations.get('device_management', '设备管理'))
        self.tabs.addTab(self.printing_params_tab, self.translations.get('printing_params', '打印参数'))
        self.tabs.addTab(self.external_data_tab, self.translations.get('external_data', '外部数据'))
        self.tabs.addTab(self.operation_log_tab, self.translations.get('operation_log', '操作日志'))

        # 布局
        layout = QVBoxLayout()
        layout.setMenuBar(self.menu_bar)  # 将菜单栏添加到布局中
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def load_all_translations(self, filename):
        """加载所有语言的翻译数据"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        full_filename = os.path.join(script_dir, filename)

        if not os.path.exists(full_filename):
            print(f"File not found: {full_filename}")
            return {}

        try:
            df = pd.read_excel(full_filename)
            all_translations = {}
            for lang in df.columns[1:]:
                all_translations[lang] = dict(zip(df['Key'], df[lang]))
            return all_translations
        except Exception as e:
            print(f"Error loading translations: {e}")
            return {}

    def change_language(self, lang):
        """改变界面语言"""
        self.lang = lang
        self.translations = self.all_translations.get(self.lang, {})
        self.update_ui_texts()

    def update_ui_texts(self):
        """更新界面上的所有文本"""
        try:
            for index, tab in enumerate([self.device_management_tab, self.printing_params_tab, self.external_data_tab, self.operation_log_tab]):
                self.tabs.setTabText(index, self.translations.get(tab.tab_name, tab.tab_name))
                tab.update_ui_texts()  # 只调用更新文本的方法
        except Exception as e:
            print(f"Error updating UI texts: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 选择语言
    language = 'English'  # 可以将其动态设定为用户选择的语言
    window = Ui_MainWindow(lang=language)

    window.show()
    sys.exit(app.exec_())
