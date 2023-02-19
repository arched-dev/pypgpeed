import tempfile
import time
import unittest
from unittest.mock import patch

from PyQt6.QtCore import Qt, QCoreApplication, QObject, QEventLoop, QEvent
from PyQt6.QtTest import QSignalSpy, QTest
from PyQt6.QtWidgets import QApplication, QLineEdit, QTextEdit, QPushButton, QMessageBox

from pypgpeed import make_key, encrypt_message, decrypt_message, encrypt_cleartext_message, verify_message as vf_msg, \
    PGP_Main

def wait_for_val(test, old_val, box):
    # wait for the field to change - also track times its checked
    times = 0
    while True:
        new_output_text = box.toPlainText()
        if times == 20:
            test.fail("Took 10 seconds with no output, thats an issue")
            return
        elif new_output_text != old_val:
            break
        time.sleep(0.5)
        times += 1
    return new_output_text
class DialogEventFilter(QObject):
    def __init__(self, callback):
        super().__init__()
        self.event_loop = QEventLoop()
        self.found = False
        self.callback = callback

    def eventFilter(self, obj, event):
        if "error" in obj.objectName():

            obj.close()
            self.event_loop.quit()
            self.found = True
            self.callback(self.found)
            return True

        return False

class MyWindowTest(unittest.TestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.person_one_pri, self.person_one_pub = make_key("person1", "person1@test.com", "TeStPaSs1!", temp_dir.name)
        self.person_two_pri, self.person_two_pub = make_key("person2", "person2@test.com", "TeStPaSs2!", temp_dir.name)
        self.app = QApplication([])
        self.window = PGP_Main()

    def tearDown(self):
        self.window.close()
        self.app.quit()

    def test_encrypt(self):
        message = "Heyy"

        # get elements
        encrypt_button = self.window.findChild(QPushButton, "encrypt_button")
        copy_button_encrypt = self.window.findChild(QPushButton, "copy_button_encrypt")
        encrypt_output_box = self.window.findChild(QTextEdit, "encrypt_output_box")
        encrypt_public_key_box = self.window.findChild(QTextEdit, "encrypt_public_key_box")
        encrypt_message_box = self.window.findChild(QTextEdit, "encrypt_message_box")

        # set the message to be encrypted
        encrypt_message_box.setText(message)
        # set the encryption box public key
        encrypt_public_key_box.setText(self.person_two_pub)
        #get the output text
        out_text = encrypt_output_box.toPlainText()
        #click the button to encrypt
        encrypt_button.click()

        #wait for the field to change - also track times its checked
        new_output_text = wait_for_val(self, out_text, encrypt_output_box)
        #get the new output text
        self.assertEqual(new_output_text[:27], '-----BEGIN PGP MESSAGE-----')

        # check copy button works
        copy_button_encrypt.click()

        # Get the contents of the clipboard
        import pyperclip
        clipboard_text = pyperclip.paste()

        self.assertIn('-----BEGIN PGP MESSAGE-----', clipboard_text)

    def test_decrypt(self):

        # create a message to send
        send_message = 'This is a test!'
        #person1 encrypt message
        encrypted_message = encrypt_message(send_message, self.person_two_pub)
        # make sure the decrypted message is the same as the original message

        decrypt_button = self.window.findChild(QPushButton, "decrypt_button")
        copy_button_decrypt = self.window.findChild(QPushButton, "copy_button_decrypt")
        decrypt_pass_box = self.window.findChild(QTextEdit, "decrypt_pass_box")
        decrypt_output_box = self.window.findChild(QTextEdit, "decrypt_output_box")
        decrypt_private_key_box = self.window.findChild(QTextEdit, "decrypt_private_key_box")
        decrypt_message_box = self.window.findChild(QTextEdit, "decrypt_message_box")

        decrypt_message_box.setText(encrypted_message)
        decrypt_private_key_box.setText(self.person_two_pri)
        decrypt_pass_box.setText("TeStPaSs2!")

        # get the output text
        out_text = decrypt_output_box.toPlainText()

        # check decrypts correctly
        # check decrypts correctly

        # click the button to encrypt
        decrypt_button.click()
        #wait for the field to change - also track times its checked
        new_output_text = wait_for_val(self, out_text, decrypt_output_box)
        # get the new output text
        self.assertEqual(new_output_text[:27], send_message)


        # check copy button works
        copy_button_decrypt.click()
        # Get the contents of the clipboard
        import pyperclip
        clipboard_text = pyperclip.paste()
        self.assertEqual(send_message, clipboard_text.strip())


        # check Fails decrypts on incorrect pass
        # check Fails decrypts on incorrect pass

        out_text = ""
        # set incorrect passphrase
        decrypt_pass_box.setText("TeStPaSs2!!!!")
        decrypt_button.click()
        #wait for the field to change - also track times its checked
        new_output_text = wait_for_val(self, out_text, decrypt_output_box)
        # get the new output text
        self.assertEqual(new_output_text, "Passphrase Error")


    def test_sign(self):

        message = "This is me"

        sign_message_box = self.window.findChild(QTextEdit, "sign_message_box")
        sign_private_key_box = self.window.findChild(QTextEdit, "sign_private_key_box")
        sign_output_box = self.window.findChild(QTextEdit, "sign_output_box")
        sign_passphrase_box = self.window.findChild(QTextEdit, "sign_passphrase_box")
        copy_button_sign = self.window.findChild(QPushButton, "copy_button_sign")
        sign_button = self.window.findChild(QPushButton, "sign_button")


        sign_message_box.setText(message)
        sign_private_key_box.setText(self.person_one_pri)
        sign_passphrase_box.setText("TeStPaSs1!")


        out_text = sign_output_box.toPlainText()

        sign_button.click()

        #wait for the field to change - also track times its checked
        new_output_text = wait_for_val(self, out_text, sign_output_box)
        # get the new output text
        self.assertIn(new_output_text[:27], "-----BEGIN PGP SIGNED MESSA")


        # check copy button works
        copy_button_sign.click()
        # Get the contents of the clipboard
        import pyperclip
        clipboard_text = pyperclip.paste()
        self.assertEqual(sign_output_box.toPlainText().strip(), clipboard_text.strip())

    def test_verify(self):
        message = "This is me"

        verify_message_box = self.window.findChild(QTextEdit, "verify_message_box")
        verify_public_key_box = self.window.findChild(QTextEdit, "verify_public_key_box")
        verify_output_box = self.window.findChild(QTextEdit, "verify_output_box")
        copy_button_verify = self.window.findChild(QTextEdit, "copy_button_verify")
        verify_button = self.window.findChild(QPushButton, "verify_button")

        signed_mess = encrypt_cleartext_message(message, self.person_one_pri, "TeStPaSs1!")

        verify_message_box.setText(message)
        verify_public_key_box.setText(self.person_one_pub)

        out_text = verify_output_box.toPlainText()

        verify_button.click()

        # wait for the field to change - also track times its checked
        new_output_text = wait_for_val(self, out_text, verify_output_box)
        # get the new output text
        self.assertEqual(new_output_text, "Message verified... It was created by the owner of this public key.")

        # check copy button works
        copy_button_verify.click()
        # Get the contents of the clipboard
        import pyperclip
        clipboard_text = pyperclip.paste()
        self.assertEqual(new_output_text, clipboard_text.strip())


    # def test_copy(self):
    #     """ checks to make sure the button doesn't copy when its blank """
    #     for button in self.window.copy_buttons:
    #
    #
    #         self.error_opened = False
    #         def callback(found):
    #             self.error_opened = found
    #
    #         dialog_event_filter = DialogEventFilter(callback)
    #         QApplication.instance().installEventFilter(dialog_event_filter)
    #         button.click()
    #
    #         # assert that the error dialog was opened and closed
    #         self.assertTrue(self.error_opened)


if __name__ == '__main__':
    unittest.main()
