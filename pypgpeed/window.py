import os
import re
import webbrowser

import pyperclip
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QGuiApplication
from PyQt6.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel, \
    QPushButton, QMessageBox, QDialog, QDialogButtonBox, QFileDialog, QCheckBox

from pypgpeed import decrypt_message, encrypt_message, encrypt_cleartext_message, verify_message, make_key
from pypgpeed.functions import get_stored_keys


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("About")

        QBtn = QDialogButtonBox.StandardButton.Ok

        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.accept)

        self.layout = QVBoxLayout()

        about_label = QLabel(
            """This is a PGP tool designed for encryped messaging.\n\nBuilt with: \npyqt6 - graphical interface \npgpy - PGP encryption""")
        about_label.setWordWrap(True)

        self.layout.addWidget(about_label)
        self.layout.addWidget(self.buttonBox)
        self.setLayout(self.layout)


class GenerateDialog(QDialog):
    keys_generated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Generate Keys")
        layout = QVBoxLayout()

        # Create widgets for "Generate Keys" tab
        self.passphrase_box = QTextEdit()
        self.passphrase_box.setTabChangesFocus(True)
        self.passphrase_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.passphrase_box.setFixedHeight(45)
        self.passphrase_box.setObjectName("gen_passphrase_box")

        self.name_box = QTextEdit()
        self.name_box.setTabChangesFocus(True)
        self.name_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.name_box.setFixedHeight(45)
        self.name_box.setObjectName("gen_name_box")

        self.email_box = QTextEdit()
        self.email_box.setTabChangesFocus(True)
        self.email_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.email_box.setFixedHeight(45)
        self.email_box.setObjectName("gen_email_box")

        self.output_location_box = QTextEdit()
        self.output_location_box.setTabChangesFocus(True)
        self.output_location_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.output_location_box.setText(os.path.expanduser('~' + "/pgp_keys"))
        self.output_location_box.setFixedHeight(45)
        self.output_location_box.setObjectName("gen_output_location_box")

        generate_button = QPushButton("Generate")
        generate_button.setObjectName("gen_generate_button")
        generate_button.clicked.connect(lambda: self.generate_key_validation())

        # Add widgets to layout
        layout.addWidget(QLabel("Create cryptographic keys for auth\n"))
        layout.addWidget(QLabel("Name (can be anything):"))
        layout.addWidget(self.name_box)
        layout.addWidget(QLabel("Email (doesn't have to be real):"))
        layout.addWidget(self.email_box)
        layout.addWidget(QLabel("Passphrase (must be secure):"))
        layout.addWidget(self.passphrase_box)
        layout.addWidget(QLabel("Output Location:"))
        layout.addWidget(self.output_location_box)
        layout.addWidget(generate_button)
        keys_saved_label = QLabel("")
        keys_saved_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(keys_saved_label)
        layout.addStretch(1)

        self.setLayout(layout)

    def _create_key(self, name, email, passphrase, output_location):
        make_key(name, email, passphrase, output_location)
        self.keys_generated.emit(output_location)
        self.close()

    def generate_key_validation(self, test=False):
        # Get the values from the text boxes
        name = self.name_box.toPlainText().strip()
        email = self.email_box.toPlainText().strip()
        passphrase = self.passphrase_box.toPlainText().strip()
        output_location = self.output_location_box.toPlainText().strip()

        # Check if the values are valid
        if not name:
            not test and QMessageBox.warning(self, "Error", "Please enter a name.")
            return False
        if not len(name) > 5:
            not test and QMessageBox.warning(self, "Error", "Please enter a longer name.")
            return False
        if not email:
            not test and QMessageBox.warning(self, "Error", "Please enter an email address.")
            return False
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            not test and QMessageBox.warning(self, "Error", "Please enter a valid email address.")
            return False
        if not passphrase:
            not test and QMessageBox.warning(self, "Error", "Please enter a passphrase.")
            return False
        if len(passphrase) < 8:
            not test and QMessageBox.warning(self, "Error", "Passphrase must be at least 8 characters long.")
            return False
        if not any(char.isupper() for char in passphrase):
            not test and QMessageBox.warning(self, "Error", "Passphrase must contain at least one uppercase letter.")
            return False
        if not any(char.islower() for char in passphrase):
            not test and QMessageBox.warning(self, "Error", "Passphrase must contain at least one lowercase letter.")
            return False
        if not any(char in "!@#$%^&*()_+{}[]|\:;<>,.?/~`" for char in passphrase):
            not test and QMessageBox.warning(self, "Error", "Passphrase must contain at least one special character.")
            return False
        if not output_location:
            not test and QMessageBox.warning(self, "Error", "Please enter an output location.")
            return False

        self._create_key(name, email, passphrase, output_location)


class PGP_Main(QMainWindow):
    error_window_shown = pyqtSignal()
    def __init__(self, test=False):
        super().__init__()

        self.test_mode = test
        self.error_window = QMessageBox()
        self.error_window.setObjectName("error_window")

        # Creates an instance of the GenerateDialog window, need this here as need to access with unittests
        self.dlg = GenerateDialog(self)

        menubar = self.menuBar()

        # file menu bar
        file_menu = menubar.addMenu('File')

        # geneate new keys dialogue open
        generate_menu = QAction('Generate New Keys', self)
        generate_menu.triggered.connect(self.generate_show)
        generate_menu.setObjectName("generate_menu")

        file_menu.addAction(generate_menu)

        # set key location open
        set_menu = QAction('Set Key Location', self)
        set_menu.triggered.connect(self.set_key_location)
        file_menu.addAction(set_menu)

        # help menu
        edit_menu = menubar.addMenu('Help')

        # open about dialogue
        help_menu = QAction('About', self)
        help_menu.triggered.connect(self.help_show)

        # open homepage
        homepage_menu = QAction('Homepage', self)
        homepage_menu.triggered.connect(self.home_show)

        edit_menu.addAction(homepage_menu)
        edit_menu.addAction(help_menu)

        # sets the location of the key files for the private and publiuc keys
        self.key_location = None
        self.key_boxes = {"private": [], "public": []}
        self.copy_buttons = []

        # Set window title
        self.setWindowTitle("PGP")
        self.setFixedWidth(800)

        # Create tabs
        self.tabs = QTabWidget()
        self.decrypt_tab = QWidget()
        self.encrypt = QWidget()
        self.sign_tab = QWidget()
        self.verify_tab = QWidget()

        self.tabs.addTab(self.decrypt_tab, "Receive / Decrypt")
        self.tabs.addTab(self.encrypt, "Send / Encrypt")
        self.tabs.addTab(self.sign_tab, "Public / Sign")
        self.tabs.addTab(self.verify_tab, "Verify")

        # Create widgets for "DECRYPT" tab
        decrypt_message_box = QTextEdit()
        decrypt_message_box.setTabChangesFocus(True)
        decrypt_message_box.setObjectName("decrypt_message_box")

        decrypt_private_key_box = QTextEdit()
        self.key_boxes["private"].append(decrypt_private_key_box)
        decrypt_private_key_box.setObjectName("decrypt_private_key_box")

        decrypt_private_key_box.setTabChangesFocus(True)

        decrypt_output_box = QTextEdit()
        decrypt_output_box.setProperty('class', 'warning')
        decrypt_output_box.setReadOnly(True)
        decrypt_output_box.setObjectName("decrypt_output_box")

        decrypt_pass_box = QTextEdit()
        decrypt_pass_box.setTabChangesFocus(True)
        decrypt_pass_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        decrypt_pass_box.setFixedHeight(45)
        decrypt_pass_box.setObjectName("decrypt_pass_box")

        decrypt_widget = QWidget()
        decrypt_hbox = QHBoxLayout(decrypt_widget)

        copy_button_decrypt = QPushButton("Copy Text")
        copy_button_decrypt.setObjectName("copy_button_decrypt")
        copy_button_decrypt.clicked.connect(
            lambda: self.copy_text(decrypt_output_box, copy_button_decrypt, True))
        copy_button_decrypt.setProperty('class', 'success')
        self.copy_buttons.append(copy_button_decrypt)

        decrypt_button = QPushButton("Generate")
        decrypt_button.setProperty('class', 'warning')
        decrypt_button.clicked.connect(
            lambda: decrypt_message(decrypt_message_box.toPlainText(), decrypt_private_key_box.toPlainText(),
                                    decrypt_pass_box.toPlainText(),
                                    decrypt_output_box))
        decrypt_button.setObjectName("decrypt_button")

        decrypt_hbox.addWidget(decrypt_button)
        decrypt_hbox.addWidget(copy_button_decrypt)

        # Add widgets to layouts
        decrypt_layout = QVBoxLayout()
        decrypt_layout.addWidget(QLabel(
            "Decrypt messages sent to you by other people\nTake a PGP message that is garbage and turn it into real text.\n"))
        decrypt_layout.addWidget(QLabel("Their PGP Message:"))
        decrypt_layout.addWidget(decrypt_message_box)
        decrypt_layout.addWidget(QLabel("Your Private Key:"))
        decrypt_layout.addWidget(decrypt_private_key_box)
        decrypt_layout.addWidget(QLabel("Your Passphrase:"))
        decrypt_layout.addWidget(decrypt_pass_box)
        decrypt_layout.addWidget(QLabel("Output:"))
        decrypt_layout.addWidget(decrypt_output_box)
        decrypt_layout.addWidget(decrypt_widget)

        # decrypt_layout.addWidget(copy_button_decrypt)
        # decrypt_layout.addWidget(decrypt_button)
        self.decrypt_tab.setLayout(decrypt_layout)

        # Create widgets for "ENCRYPT" tab

        encrypt_message_box = QTextEdit()
        encrypt_message_box.setTabChangesFocus(True)
        encrypt_message_box.setObjectName("encrypt_message_box")


        encrypt_public_key_box = QTextEdit()
        encrypt_public_key_box.setTabChangesFocus(True)
        encrypt_public_key_box.setObjectName("encrypt_public_key_box")



        encrypt_output_box = QTextEdit()
        encrypt_output_box.setProperty('class', 'warning')
        encrypt_output_box.setReadOnly(True)
        encrypt_output_box.setObjectName("encrypt_output_box")


        encrypt_widget = QWidget()
        encrypt_hbox = QHBoxLayout(encrypt_widget)

        copy_button_encrypt = QPushButton("Copy Text")
        copy_button_encrypt.clicked.connect(
            lambda: self.copy_text(encrypt_output_box, copy_button_encrypt))
        copy_button_encrypt.setProperty('class', 'success')
        self.copy_buttons.append(copy_button_encrypt)
        copy_button_encrypt.setObjectName("copy_button_encrypt")


        encrypt_button = QPushButton("Generate")
        encrypt_button.setProperty('class', 'warning')
        encrypt_button.clicked.connect(
            lambda: encrypt_message(encrypt_message_box.toPlainText(), encrypt_public_key_box.toPlainText(),
                                    encrypt_output_box))
        encrypt_button.setObjectName("encrypt_button")

        encrypt_hbox.addWidget(encrypt_button)
        encrypt_hbox.addWidget(copy_button_encrypt)

        # Add widgets to layouts
        encrypt_layout = QVBoxLayout()
        encrypt_layout.addWidget(QLabel(
            "Encrypt messages to other people\nTake real text and make it into garbage that only be decrypted by someone with your pypgpeed public key.\n"))
        encrypt_layout.addWidget(QLabel("Your Message:"))
        encrypt_layout.addWidget(encrypt_message_box)
        encrypt_layout.addWidget(QLabel("Their Public Key:"))
        encrypt_layout.addWidget(encrypt_public_key_box)
        encrypt_layout.addWidget(QLabel("Output:"))
        encrypt_layout.addWidget(encrypt_output_box)
        encrypt_layout.addWidget(encrypt_widget)
        # encrypt_layout.addWidget(copy_button_encrypt)
        # encrypt_layout.addWidget(encrypt_button)

        self.encrypt.setLayout(encrypt_layout)

        # Create widgets for "SIGN" tab
        sign_message_box = QTextEdit()
        sign_message_box.setTabChangesFocus(True)
        sign_message_box.setObjectName("sign_message_box")

        sign_private_key_box = QTextEdit()
        self.key_boxes["private"].append(sign_private_key_box)
        sign_private_key_box.setTabChangesFocus(True)
        sign_private_key_box.setObjectName("sign_private_key_box")

        sign_output_box = QTextEdit()
        sign_output_box.setProperty('class', 'warning')
        sign_output_box.setReadOnly(True)
        sign_output_box.setObjectName("sign_output_box")

        sign_passphrase_box = QTextEdit()
        sign_passphrase_box.setFixedHeight(45)
        sign_passphrase_box.setTabChangesFocus(True)
        sign_passphrase_box.setObjectName("sign_passphrase_box")


        sign_widget = QWidget()
        sign_hbox = QHBoxLayout(sign_widget)

        copy_button_sign = QPushButton("Copy Text")
        copy_button_sign.clicked.connect(
            lambda: self.copy_text(sign_output_box, copy_button_sign))
        copy_button_sign.setProperty('class', 'success')
        self.copy_buttons.append(copy_button_sign)
        copy_button_sign.setObjectName("copy_button_sign")


        sign_button = QPushButton("Generate")
        sign_button.setProperty('class', 'warning')

        sign_button.clicked.connect(
            lambda: encrypt_cleartext_message(sign_message_box.toPlainText(), sign_private_key_box.toPlainText(),
                                              sign_passphrase_box.toPlainText(), sign_output_box))
        sign_button.setObjectName("sign_button")

        sign_hbox.addWidget(sign_button)
        sign_hbox.addWidget(copy_button_sign)

        # Add widgets to layouts
        sign_layout = QVBoxLayout()
        sign_layout.addWidget(QLabel(
            "Sign a message to prove it is you sending the message\nCreate a message that is visible but has been signed by you, prooving you are the writer of the message.\n"))
        sign_layout.addWidget(QLabel("Message:"))
        sign_layout.addWidget(sign_message_box)
        sign_layout.addWidget(QLabel("Your Private Key:"))
        sign_layout.addWidget(sign_private_key_box)
        sign_layout.addWidget(QLabel("Your Passphrase:"))
        sign_layout.addWidget(sign_passphrase_box)
        sign_layout.addWidget(QLabel("Output:"))
        sign_layout.addWidget(sign_output_box)
        sign_layout.addWidget(sign_widget)
        # sign_layout.addWidget(copy_button_sign)
        # sign_layout.addWidget(sign_button)
        self.sign_tab.setLayout(sign_layout)

        # Create widgets for "VERIFY" tab
        verify_message_box = QTextEdit()
        verify_message_box.setTabChangesFocus(True)
        verify_message_box.setObjectName("verify_message_box")

        verify_public_key_box = QTextEdit()
        self.key_boxes["public"].append(verify_public_key_box)
        verify_public_key_box.setTabChangesFocus(True)
        verify_public_key_box.setObjectName("verify_public_key_box")


        verify_output_box = QTextEdit()
        verify_output_box.setProperty('class', 'warning')
        verify_output_box.setReadOnly(True)
        verify_output_box.setObjectName("verify_output_box")


        verify_widget = QWidget()
        verify_hbox = QHBoxLayout(verify_widget)

        copy_button_verify = QPushButton("Copy Text")
        copy_button_verify.clicked.connect(
            lambda: self.copy_text(verify_output_box, copy_button_verify))
        copy_button_verify.setProperty('class', 'success')
        self.copy_buttons.append(copy_button_verify)
        copy_button_verify.setObjectName("copy_button_verify")

        verify_button = QPushButton("Generate")
        verify_button.setProperty('class', 'warning')
        verify_button.clicked.connect(
            lambda: verify_message(verify_message_box.toPlainText(), verify_public_key_box.toPlainText(),
                                   verify_output_box))
        verify_button.setObjectName("verify_button")


        verify_hbox.addWidget(verify_button)
        verify_hbox.addWidget(copy_button_verify)

        # Add widgets to layouts
        verify_layout = QVBoxLayout()
        verify_layout.addWidget(QLabel("Verify a signed message that has been sent\n"))
        verify_layout.addWidget(QLabel("Message:"))
        verify_layout.addWidget(verify_message_box)
        verify_layout.addWidget(QLabel("Their Public Key:"))
        verify_layout.addWidget(verify_public_key_box)
        verify_layout.addWidget(QLabel("Output:"))
        verify_layout.addWidget(verify_output_box)
        verify_layout.addWidget(verify_widget)
        # verify_layout.addWidget(copy_button_verify)
        # verify_layout.addWidget(verify_button)
        self.verify_tab.setLayout(verify_layout)

        # Set main layout and add tabs
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.tabs)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.setup_keys()

    def copy_text(self, textbox, copyButton, needs_pgp=True):
        # Copy the text from the text box to the clipboard
        text = textbox.toPlainText()
        if not text:
            if needs_pgp and not "---" in text or not needs_pgp:

                self.error_window.warning(self, "Error", "Nothing to copy...")
                return

        clipboard = QGuiApplication.clipboard()
        try:
            clipboard.setText(text)
            pyperclip.copy(text)
        except:
            QMessageBox.warning(self, "Error", "Error copying")
            return

        # Change the button text to "Copied"
        copyButton.setText("Copied")

        # Wait for 3 seconds
        QTimer.singleShot(1500, self._return_box_to_normal)


    def _return_box_to_normal(self):
        for box in self.copy_buttons:
            # Change the button text back to "Copy Text"
            box.setText("Copy Text")


    def setup_keys(self, check=False):
        """adds the private and public keys to the window."""
        pri, pub = get_stored_keys(self.key_location)

        if check and (not pri or not pub):
            msg_box = QMessageBox()
            msg_box.setWindowTitle("Keys Error")
            msg_box.setText(
                f"Either the public key, or private key is not found in {self.key_location}, make sure the files are named 'pub_key.key' & 'pri_key.key'")
            msg_box.exec()
            return

        # loop items with pri or public keys
        for k, v in self.key_boxes.items():
            for el in v:
                if k == "private":
                    el.setText(pri.strip())
                else:
                    el.setText(pub.strip())

    def help_show(self):
        # Creates an instance of the AboutDialog window
        dlg = AboutDialog(self)
        # Executes the AboutDialog window
        dlg.exec()

    def home_show(self):
        # Defines a URL to be opened in the default web browser
        url = 'https://github.com/lewis-morris/pypgpeed'
        # Opens the specified URL in the default web browser
        webbrowser.open(url)

    def generate_show(self):
        # Connects the key_generated signal from the GenerateDialog to the on_key_generated slot of the parent window
        self.dlg.keys_generated.connect(self._set_key)
        # Executes the GenerateDialog window
        self.dlg.exec()
        # Runs the setup_keys function after the GenerateDialog window is closed

    def _set_key(self, location):
        # Sets the key_location attribute to the specified location

        self.key_location = location

        if not self.test_mode:
            QMessageBox.information(self, "Keys generated", "New keys have been generated.")

        self.setup_keys(True)

    def set_key_location(self):
        loc = QFileDialog.getExistingDirectory(self, 'Select Folder', "/home")
        if loc:
            self.key_location = loc
            self.setup_keys(True)



