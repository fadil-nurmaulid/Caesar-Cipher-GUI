# Caesar_Cipher
"Made by Fadil Nurmaulid"

import sys, os
import string
from random import randint
from PyQt5.QtWidgets import (QApplication, QWidget, QStackedWidget, QLabel, 
                             QPushButton, QSizePolicy, QHBoxLayout, QVBoxLayout,
                             QTextEdit, QCheckBox)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QFontDatabase, QIcon

# 🔐 Logic Class
class CaesarCipher:
    def __init__(self):
        self.lowercase = list(string.ascii_lowercase)
        self.uppercase = list(string.ascii_uppercase)
        self.original = self.lowercase + self.uppercase
    
    def caesar(self, text, shift):
        shifted_lower = self.lowercase[shift:] + self.lowercase[:shift]
        shifted_upper = self.uppercase[shift:] + self.uppercase[:shift]
        shifted_alphabet = shifted_lower + shifted_upper

        result = ""
        for char in text:
            if char in self.original:
                index = self.original.index(char)
                result += shifted_alphabet[index]
            else:
                result += char
        return result

# 🎨 UI Class
class CaesarCipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Caesar Cipher")
        self.setFixedSize(700, 400)

        self.cipher = CaesarCipher()

        # Custom Window Icon
        icon_path = os.path.join(os.path.dirname(__file__), "assets/Icon.ico")
        self.setWindowIcon(QIcon(icon_path))

        # Custom Font
        font_path = os.path.join(os.path.dirname(__file__), "assets/FiraCode-Bold.ttf")
        font_id = QFontDatabase.addApplicationFont(font_path)
        font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
        self.my_font = QFont(font_family)

        # Initiate Page Interface
        self.main_page = self.main_page_ui()
        self.encrypt_page = self.encrypt_ui()
        self.decrypt_page = self.decrypt_ui()

        # Creating QStackedWidget and Adding Pages
        self.stack = QStackedWidget()
        self.stack.addWidget(self.main_page)    # Index 0
        self.stack.addWidget(self.encrypt_page) # Index 1
        self.stack.addWidget(self.decrypt_page) # Index 2

        # Main Layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.stack)
        self.setLayout(main_layout)
        
    def main_page_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        hbox = QHBoxLayout()

        label = QLabel("CAESAR CIPHER")
        encrypt_button = QPushButton("Encrypt")
        decrypt_button = QPushButton("Decrypt")
        encrypt_button.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        decrypt_button.clicked.connect(lambda: self.stack.setCurrentIndex(2))

        label.setAlignment(Qt.AlignCenter)
        label.setFont(self.my_font)

        for i in (encrypt_button, decrypt_button):
            i.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            i.setFont(QFont("Segoe UI"))

        # Styling
        self.default_copy_button_style = """QPushButton#copy_btn{
                background-color: #f7f7f7;
                border: 1px solid hsl(0, 0%, 75%);
                border-radius: 5px;
                padding: 5px 10px;
                font-size: 12pt;
                color: #333333;
            }
            QPushButton:hover#copy_btn{
                background-color: hsl(0, 0%, 88%);
                border: 1px solid hsl(0, 0%, 65%);
            }
            QPushButton:pressed#copy_btn{
                background-color: hsl(0, 0%, 80%);
                border: 1px solid hsl(0, 0%, 60%);
            }
            QPushButton:disabled#copy_btn{
                background-color: #e0e0e0;
                color: #999999;
                border: 1px solid hsl(0, 0%, 75%);
            }"""
        page.setStyleSheet("""
            QPushButton, QLabel{
                padding: 10px;
                border: 2px solid black;  
                border-radius: 5px;
            }
            QLabel{
                letter-spacing: 2px;               
                font-size: 65px;
                background-color: hsl(80, 190, 80);
                padding: 6px 12px;
            }
            QPushButton{
                font-size: 40px;
                background-color: gray;          
            }
            QPushButton:hover{
                background-color: hsl(0, 0, 88);               
            }
            QPushButton:pressed{
                background-color: hsl(0, 0, 80); 
            }
        """)

        hbox.addWidget(encrypt_button)
        hbox.addWidget(decrypt_button)
        layout.addWidget(label)
        layout.addLayout(hbox)
        page.setLayout(layout)

        return page

    def encrypt_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        hbox0 = QHBoxLayout()
        hbox1 = QHBoxLayout()
        hbox2 = QHBoxLayout()

        self.shift_encrypt_value = 0
        self.encrypt_shift_timer = QTimer()
        self.encrypt_shift_timer.timeout.connect(lambda: self.handle_shift_value_encrypt(self._held_encrypt_operation))

        # layout widget
        self.encrypt_input = QTextEdit()
        self.encrypt_input.setPlaceholderText("Enter text to encrypt...")
        self.encrypt_input.setFont(self.my_font)
        self.encrypt_input.setObjectName("txt_input")

        self.encrypt_output = QTextEdit()
        self.encrypt_output.setPlaceholderText("Encrypted result will appear here")
        self.encrypt_output.setFont(self.my_font)
        self.encrypt_output.setReadOnly(True)
        self.encrypt_output.setObjectName("txt_output")

        # hbox0 widget
        back_button = QPushButton("\u2B05")
        back_button.setFont(self.my_font)
        back_button.setObjectName("back_btn")

        title_label = QLabel("Caesar Cipher: Encrypt")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        title_label.setFont(self.my_font)
        title_label.setObjectName("title_lbl")

        # hbox1 widget
        self.encrypt_shift_label = QLabel("Shift:")
        self.encrypt_shift_label.setFont(self.my_font)
        self.encrypt_shift_label.setObjectName("shift_lbl")

        self.minus_button_encrypt = QPushButton("-")
        self.minus_button_encrypt.setFont(self.my_font)
        self.minus_button_encrypt.setObjectName("minus_btn")

        self.shift_encrypt_value_label = QLabel("00")
        self.shift_encrypt_value_label.setFont(self.my_font)
        self.shift_encrypt_value_label.setObjectName("shift_value_lbl")
        
        self.plus_button_encrypt = QPushButton("+")
        self.plus_button_encrypt.setFont(self.my_font)
        self.plus_button_encrypt.setObjectName("plus_btn")

        spacing_label = QLabel("\u00A9 2025 Fadil Nurmaulid")
        spacing_label.setStyleSheet("font-size: 8pt")
        spacing_label.setAlignment(Qt.AlignCenter)
        spacing_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.random_checkbox = QCheckBox("use random shift")
        self.random_checkbox.setFont(self.my_font)
        self.random_checkbox.setObjectName("random_cbx")

        # hbox2 widget
        self.encrypt_button = QPushButton("🔒 Encrypt")
        self.encrypt_button.setFont(self.my_font)
        self.encrypt_button.setDisabled(True)
        self.encrypt_button.setObjectName("encrypt_btn")

        self.encrypt_reset_button = QPushButton("\U0001F501 Reset")
        self.encrypt_reset_button.setFont(self.my_font)
        self.encrypt_reset_button.setDisabled(True)   
        self.encrypt_reset_button.setObjectName("reset_btn")

        self.encrypt_copy_button = QPushButton("\U0001F4CB Copy")
        self.encrypt_copy_button.setFont(self.my_font)
        self.encrypt_copy_button.setDisabled(True)
        self.encrypt_copy_button.setObjectName("copy_btn")

        # Styling
        self.encrypt_copy_button.setStyleSheet(self.default_copy_button_style)
        page.setStyleSheet("""
            QPushButton#back_btn{
                padding: 10px;
                border: 2px solid black;  
                border-radius: 5px;
                font-size: 30px;
                background-color: gray;
            }
            QPushButton:hover#back_btn{
                background-color: hsl(0, 0, 88);
            }
            QPushButton:pressed#back_btn{
                background-color: hsl(0, 0, 80);               
            }
            QPushButton#minus_btn, QPushButton#plus_btn{
                background-color: #f0f0f0;
                border: 1px solid hsl(0, 0, 80);
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12pt;
                color: #333;            
            }
            QPushButton:hover#minus_btn, QPushButton:hover#plus_btn{
                background-color: hsl(210, 60, 92);
                border: 1px solid hsl(210, 60, 60)               
            }
            QPushButton:pressed#minus_btn, QPushButton:pressed#plus_btn{
                background-color: hsl(210, 60, 80);               
            }
            QPushButton:disabled#minus_btn, QPushButton:disabled#plus_btn{
                background-color: #e0e0e0;
                color: #999999;
                border: 1px solid hsl(0, 0, 75);               
            }
            QPushButton#encrypt_btn{
                background-color: hsl(210, 100, 55);
                border: 1px solid hsl(210, 100, 40);
                border-radius: 6px;
                padding: 6px 14px;
                font-size: 13pt;
                color: white;
            }
            QPushButton:hover#encrypt_btn{
                background-color: hsl(210, 100, 65);
                border: 1px solid hsl(210, 100, 50);
            }
            QPushButton:pressed#encrypt_btn{
                background-color: hsl(210, 100, 45);
                border: 1px solid hsl(210, 100, 35);
            }
            QPushButton:disabled#encrypt_btn{
                background-color: #cccccc;
                border: 1px solid #aaaaaa;
                color: #666666;               
            }
            QPushButton#reset_btn{
                background-color: #f5f5f5;
                border: 1px solid hsl(0, 0, 75);
                border-radius: 5px;
                padding: 5px 12px;
                font-size: 12pt;
                color: #333333;    
            }
            QPushButton:hover#reset_btn{
                background-color: hsl(0, 0%, 88%);
                border: 1px solid hsl(0, 0%, 65%);
            }
            QPushButton:pressed#reset_btn{
                background-color: hsl(0, 0%, 80%);
                border: 1px solid hsl(0, 0%, 60%);
            }
            QPushButton:disabled#reset_btn{
                background-color: #e0e0e0;
                color: #999999;
                border: 1px solid hsl(0, 0%, 75%);
            }
            QLabel#shift_value_lbl, QLabel#shift_lbl{
                font-size: 12pt;
                color: #222;
            }
            QLabel#title_lbl{
                padding: 10px;
                border: 2px solid black;  
                border-radius: 5px;
                background-color: hsl(80, 190, 80);
                font-size: 30px;
            }
            QCheckBox#random_cbx{
                font-size: 12pt;
                color: #202020;
            }
            QCheckBox::indicator#random_cbx{
                width: 16px;
                height: 16px;
                border: 1px solid hsl(0, 0, 60);
                border-radius: 3px;
                background-color: #f5f5f5;               
            }
            QCheckBox::indicator:checked#random_cbx{
                background-color: hsl(210, 100, 60);          
            }
            QCheckBox:hover#random_cbx{
                color: hsl(210, 100, 40);               
            }
            QTextEdit#txt_input{
                background-color: #ffffff;
                border: 1px solid hsl(0, 0, 80);
                border-radius: 6px;
                padding: 6px;
                font-size: 13pt;
                color: #202020;
            }
            QTextEdit:focus#txt_input{
                border: 1.5px solid hsl(210, 100, 60);
                background-color: #fcfcfc;               
            }
            QTextEdit#txt_output{
                background-color: #f9f9f9;
                border: 1px solid hsl(0, 0, 80);
                border-radius: 6px;
                padding: 8px 10px;
                font-size: 13pt;
                color: #202020;
            }
            QTextEdit:disabled#txt_output{
                background-color: #f0f0f0;
                color: #999999;
                border: 1px solid hsl(0, 0, 75);               
            }
        """)

        # ======Event======
        # Click
        back_button.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.plus_button_encrypt.clicked.connect(lambda: self.handle_shift_value_encrypt("plus"))
        self.minus_button_encrypt.clicked.connect(lambda: self.handle_shift_value_encrypt("minus"))
        self.encrypt_button.clicked.connect(self.handle_encrypt)
        self.encrypt_reset_button.clicked.connect(self.handle_reset_encrypt)
        self.encrypt_copy_button.clicked.connect(self.handle_copy_encrypt)

        # Hold
        self.plus_button_encrypt.pressed.connect(lambda: self.handle_shift_value_encrypt("plus", "hold"))
        self.plus_button_encrypt.released.connect(lambda: self.encrypt_shift_timer.stop())
        self.minus_button_encrypt.pressed.connect(lambda: self.handle_shift_value_encrypt("minus", "hold"))
        self.minus_button_encrypt.released.connect(lambda: self.encrypt_shift_timer.stop())

        # Check
        self.random_checkbox.stateChanged.connect(self.handle_random_shift)     

        # Text
        self.encrypt_input.textChanged.connect(self.handle_encrypt_textChanged)

        # =================

        hbox0.addWidget(back_button)
        hbox0.addWidget(title_label)
        
        hbox1.addWidget(self.encrypt_shift_label)
        hbox1.addWidget(self.minus_button_encrypt)
        hbox1.addWidget(self.shift_encrypt_value_label)
        hbox1.addWidget(self.plus_button_encrypt)
        hbox1.addWidget(spacing_label)
        hbox1.addWidget(self.random_checkbox)

        hbox2.addWidget(self.encrypt_button)
        hbox2.addSpacing(10)
        hbox2.addWidget(self.encrypt_reset_button)
        hbox2.addSpacing(10)
        hbox2.addWidget(self.encrypt_copy_button)
        
        layout.addLayout(hbox0)
        layout.addWidget(self.encrypt_input)
        layout.addLayout(hbox1)
        layout.addLayout(hbox2)
        layout.addWidget(self.encrypt_output)
        page.setLayout(layout)

        return page
    
    # =========================
    # 🔐 ENCRYPT PAGE HANDLERS
    # =========================

    def handle_encrypt(self):
        text = self.encrypt_input.toPlainText()
        self.encrypt_copy_button.setDisabled(False)
        if not self.random_checkbox.isChecked():
            text_output = self.cipher.caesar(text, self.shift_encrypt_value)
        else:
            text_output = self.cipher.caesar(text, randint(1, 25))
        
        self.encrypt_output.setPlainText(text_output)

    def handle_encrypt_textChanged(self):
        text = self.encrypt_input.toPlainText()
        text_output = self.encrypt_output.toPlainText()
        if bool(text) and bool(text_output):
            self.encrypt_button.setDisabled(False)
            self.encrypt_reset_button.setDisabled(False)
        elif bool(text) and not bool(text_output):
            self.encrypt_button.setDisabled(False)
            self.encrypt_reset_button.setDisabled(False)
        elif not bool(text) and bool(text_output):
            self.encrypt_button.setDisabled(True)
            self.encrypt_reset_button.setDisabled(False)
        elif not (bool(text) and bool(text_output)):
            self.encrypt_reset_button.setDisabled(True)
            self.encrypt_button.setDisabled(True)

    def handle_reset_encrypt(self):
        self.encrypt_input.setPlainText("")
        self.shift_encrypt_value = 0
        self.shift_encrypt_value_label.setText("00")
        self.random_checkbox.setCheckState(False)
        self.encrypt_reset_button.setDisabled(True)
        self.encrypt_copy_button.setDisabled(True)
        self.encrypt_output.setPlainText("")

    def handle_copy_encrypt(self):
        text = self.encrypt_output.toPlainText()
        QApplication.clipboard().setText(text)
        self.encrypt_copy_button.setStyleSheet("""
            background-color: hsl(120, 60, 70);
            color: white;
            border: 1px solid hsl(120, 60, 60);
            border-radius: 5px;
            padding: 5px 10px;
            font-size: 12pt;
        """)
        original_text = self.encrypt_copy_button.text()
        self.encrypt_copy_button.setText("✅Copied!")
        QTimer.singleShot(1500, self.reset_copy_button_encrypt)

    def reset_copy_button_encrypt(self):
        self.encrypt_copy_button.setStyleSheet(self.default_copy_button_style)
        self.encrypt_copy_button.setText("\U0001F4CB Copy")

    def handle_shift_value_encrypt(self, operation, state="click"):
        if not self.random_checkbox.isChecked():
            if state == "click":
                if operation == "minus":
                    if self.shift_encrypt_value > 0:
                        self.shift_encrypt_value -= 1
                elif operation == "plus":
                    self.shift_encrypt_value = (self.shift_encrypt_value + 1) % 27
                self.shift_encrypt_value_label.setText(f"{self.shift_encrypt_value:02}")
            elif state == "hold":
                self._held_encrypt_operation = operation
                self.encrypt_shift_timer.start(150)

    def handle_random_shift(self):
        if self.random_checkbox.isChecked():
            self.minus_button_encrypt.setDisabled(True)
            self.plus_button_encrypt.setDisabled(True)
            self.encrypt_shift_label.setStyleSheet("color: #999999")  
            self.shift_encrypt_value_label.setStyleSheet("color: #999999")        
        else:
            self.minus_button_encrypt.setDisabled(False)
            self.plus_button_encrypt.setDisabled(False)
            self.encrypt_shift_label.setStyleSheet("color: #222")  
            self.shift_encrypt_value_label.setStyleSheet("color: #222")
    
    def decrypt_ui(self):
        page = QWidget()
        layout = QVBoxLayout()
        hbox0 = QHBoxLayout()
        hbox1 = QHBoxLayout()
        hbox2 = QHBoxLayout()

        self.shift_decrypt_value = 0
        self.decrypt_shift_timer = QTimer()
        self.decrypt_shift_timer.timeout.connect(lambda: self.handle_shift_value_decrypt(self._held_decrypt_operation))

        # layout widget
        self.decrypt_input = QTextEdit()
        self.decrypt_input.setPlaceholderText("Enter text to decrypt...")
        self.decrypt_input.setFont(self.my_font)
        self.decrypt_input.setObjectName("txt_input")
        
        self.decrypt_output = QTextEdit()
        self.decrypt_output.setPlaceholderText("Decrypted result will appear here")
        self.decrypt_output.setFont(self.my_font)
        self.decrypt_output.setReadOnly(True)
        self.decrypt_output.setObjectName("txt_output")

        # hbox0 widget
        back_button = QPushButton("\u2B05")
        back_button.setFont(self.my_font)
        back_button.setObjectName("back_btn")

        title_label = QLabel("Caesar Cipher: Decrypt")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        title_label.setFont(self.my_font)
        title_label.setObjectName("title_lbl")

        # hbox1 widget
        self.decrypt_shift_label = QLabel("Shift:")
        self.decrypt_shift_label.setFont(self.my_font)
        self.decrypt_shift_label.setObjectName("shift_lbl")

        self.minus_button_decrypt = QPushButton("-")
        self.minus_button_decrypt.setFont(self.my_font)
        self.minus_button_decrypt.setObjectName("minus_btn")

        self.shift_decrypt_value_label = QLabel("00")
        self.shift_decrypt_value_label.setFont(self.my_font)
        self.shift_decrypt_value_label.setObjectName("shift_value_lbl")

        self.plus_button_decrypt = QPushButton("+")
        self.plus_button_decrypt.setFont(self.my_font)
        self.plus_button_decrypt.setObjectName("plus_btn")

        spacing_label = QLabel("\u00A9 2025 Fadil Nurmaulid")
        spacing_label.setStyleSheet("font-size: 8pt")
        spacing_label.setAlignment(Qt.AlignCenter)
        spacing_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # hbox2 widget
        self.decrypt_reset_button = QPushButton("\U0001F501 Reset")
        self.decrypt_reset_button.setFont(self.my_font)
        self.decrypt_reset_button.setDisabled(True)
        self.decrypt_reset_button.setObjectName("reset_btn")

        self.decrypt_copy_button = QPushButton("\U0001F4CB Copy")
        self.decrypt_copy_button.setFont(self.my_font)
        self.decrypt_copy_button.setDisabled(True)
        self.decrypt_copy_button.setObjectName("copy_btn")

        # Styling
        self.decrypt_copy_button.setStyleSheet(self.default_copy_button_style)
        page.setStyleSheet("""
            QPushButton#back_btn{
                padding: 10px;
                border: 2px solid black;  
                border-radius: 5px;
                font-size: 30px;
                background-color: gray;
            }
            QPushButton:hover#back_btn{
                background-color: hsl(0, 0, 88);
            }
            QPushButton:pressed#back_btn{
                background-color: hsl(0, 0, 80);               
            }
            QPushButton#minus_btn, QPushButton#plus_btn{
                background-color: #f0f0f0;
                border: 1px solid hsl(0, 0, 80);
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12pt;
                color: #333;            
            }
            QPushButton:hover#minus_btn, QPushButton:hover#plus_btn{
                background-color: hsl(210, 60, 92);
                border: 1px solid hsl(210, 60, 60)               
            }
            QPushButton:pressed#minus_btn, QPushButton:pressed#plus_btn{
                background-color: hsl(210, 60, 80);               
            }
            QPushButton#reset_btn{
                background-color: #f5f5f5;
                border: 1px solid hsl(0, 0, 75);
                border-radius: 5px;
                padding: 5px 12px;
                font-size: 12pt;
                color: #333333;    
            }
            QPushButton:hover#reset_btn{
                background-color: hsl(0, 0%, 88%);
                border: 1px solid hsl(0, 0%, 65%);
            }
            QPushButton:pressed#reset_btn{
                background-color: hsl(0, 0%, 80%);
                border: 1px solid hsl(0, 0%, 60%);
            }
            QPushButton:disabled#reset_btn{
                background-color: #e0e0e0;
                color: #999999;
                border: 1px solid hsl(0, 0%, 75%);
            }
            QLabel#shift_value_lbl, QLabel#shift_lbl{
                font-size: 12pt;
                color: #222;
            }
            QLabel#title_lbl{
                padding: 10px;
                border: 2px solid black;  
                border-radius: 5px;
                background-color: hsl(80, 190, 80);
                font-size: 30px;
            }
            QTextEdit#txt_input{
                background-color: #ffffff;
                border: 1px solid hsl(0, 0, 80);
                border-radius: 6px;
                padding: 6px;
                font-size: 13pt;
                color: #202020;
            }
            QTextEdit:focus#txt_input{
                border: 1.5px solid hsl(210, 100, 60);
                background-color: #fcfcfc;               
            }
            QTextEdit#txt_output{
                background-color: #f9f9f9;
                border: 1px solid hsl(0, 0, 80);
                border-radius: 6px;
                padding: 8px 10px;
                font-size: 13pt;
                color: #202020;
            }
            QTextEdit:disabled#txt_output{
                background-color: #f0f0f0;
                color: #999999;
                border: 1px solid hsl(0, 0, 75);               
            }
        """)

        # ======Event======
        # Click
        back_button.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.plus_button_decrypt.clicked.connect(lambda: self.handle_shift_value_decrypt("plus"))
        self.minus_button_decrypt.clicked.connect(lambda: self.handle_shift_value_decrypt("minus"))
        self.decrypt_reset_button.clicked.connect(self.handle_reset_decrypt)
        self.decrypt_copy_button.clicked.connect(self.handle_copy_decrypt)

        # Hold
        self.plus_button_decrypt.pressed.connect(lambda: self.handle_shift_value_decrypt("plus", "hold"))
        self.plus_button_decrypt.released.connect(lambda: self.decrypt_shift_timer.stop())
        self.minus_button_decrypt.pressed.connect(lambda: self.handle_shift_value_decrypt("minus", "hold"))
        self.minus_button_decrypt.released.connect(lambda: self.decrypt_shift_timer.stop())

        # Text
        self.decrypt_input.textChanged.connect(self.handle_decrypt_textChanged)

        # =================

        hbox0.addWidget(back_button)
        hbox0.addWidget(title_label)

        hbox1.addSpacing(10)
        hbox1.addWidget(self.decrypt_shift_label)
        hbox1.addWidget(self.minus_button_decrypt)
        hbox1.addWidget(self.shift_decrypt_value_label)
        hbox1.addWidget(self.plus_button_decrypt)
        hbox1.addWidget(spacing_label)

        hbox2.addSpacing(10)
        hbox2.addWidget(self.decrypt_reset_button)
        hbox2.addWidget(self.decrypt_copy_button)
        hbox2.addSpacing(10)

        layout.addLayout(hbox0)
        layout.addWidget(self.decrypt_input)
        layout.addLayout(hbox1)
        layout.addLayout(hbox2)
        layout.addWidget(self.decrypt_output)
        page.setLayout(layout)

        return page
    
    # =========================
    # 🔓 DECRYPT PAGE HANDLERS
    # =========================

    def handle_decrypt_textChanged(self):
        text = self.decrypt_input.toPlainText()
        decrypted_text = self.cipher.caesar(text, self.shift_decrypt_value)
        self.decrypt_output.setPlainText(decrypted_text)
        text_output = self.decrypt_output.toPlainText()
        self.decrypt_copy_button.setDisabled(False)
        if bool(text) and bool(text_output):
            self.decrypt_reset_button.setDisabled(False)
            self.decrypt_copy_button.setDisabled(False)
        else:
            self.decrypt_reset_button.setDisabled(True)
            self.decrypt_copy_button.setDisabled(True)

    def handle_reset_decrypt(self):
        self.decrypt_input.setPlainText("")
        self.shift_decrypt_value = 0
        self.shift_decrypt_value_label.setText("00")
        self.decrypt_reset_button.setDisabled(True)
        self.decrypt_copy_button.setDisabled(True)
        self.decrypt_output.setPlainText("")

    def handle_copy_decrypt(self):
        text = self.decrypt_output.toPlainText()
        QApplication.clipboard().setText(text)
        self.decrypt_copy_button.setStyleSheet("""
            background-color: hsl(120, 60, 70);
            color: white;
            border: 1px solid hsl(120, 60, 60);
            border-radius: 5px;
            padding: 5px 10px;
            font-size: 12pt;
        """)
        self.decrypt_copy_button.setText("✅Copied!")
        QTimer.singleShot(1500, self.reset_copy_button_decrypt)

    def reset_copy_button_decrypt(self):
        self.decrypt_copy_button.setStyleSheet(self.default_copy_button_style)
        self.decrypt_copy_button.setText("\U0001F4CB Copy")

    def handle_shift_value_decrypt(self, operation, state="click"):
        text = self.decrypt_input.toPlainText()
        if state == "click":
            if operation == "minus":
                if self.shift_decrypt_value > 0:
                    self.shift_decrypt_value -= 1
            elif operation == "plus":
                self.shift_decrypt_value = (self.shift_decrypt_value + 1) % 27
            self.shift_decrypt_value_label.setText(f"{self.shift_decrypt_value:02}")
        elif state == "hold":
            self._held_decrypt_operation = operation
            self.decrypt_shift_timer.start(150)
        decrypted_text = self.cipher.caesar(text, self.shift_decrypt_value)
        self.decrypt_output.setText(decrypted_text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CaesarCipherApp()
    window.show()
    sys.exit(app.exec_())