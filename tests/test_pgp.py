import tempfile
import unittest

from pypgpeed import make_key, encrypt_message, decrypt_message, encrypt_cleartext_message, verify_message as vf_msg


class MyPGPTest(unittest.TestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.person_one_pri, self.person_one_pub = make_key("person1", "person1@test.com", "TeStPaSs1!", temp_dir.name)
        self.person_two_pri, self.person_two_pub = make_key("person2", "person2@test.com", "TeStPaSs2!", temp_dir.name)

    def test_unlock_fail(self):
        # create a message to send
        send_message = 'This is a test!'
        # person1 encrypt message
        encrypted_message = encrypt_message(send_message, self.person_two_pub)
        # person2 decrypt message
        decrypted_message = decrypt_message(encrypted_message, self.person_one_pri, "NotTheCorrectPasss!!")
        # make sure the decrypted message is the same as the original message
        self.assertFalse(decrypted_message)
    def test_encrypt_and_decrypt(self):
        # create a message to send
        send_message = 'This is a test!'
        #person1 encrypt message
        encrypted_message = encrypt_message(send_message, self.person_two_pub)
        #person2 decrypt message
        decrypted_message = decrypt_message(encrypted_message, self.person_two_pri, "TeStPaSs2!")
        # make sure the decrypted message is the same as the original message
        self.assertEqual(decrypted_message, send_message)

    def test_failed_encrypt_and_decrypt(self):
        # create a message to send
        send_message = 'This is a test!'
        #person1 encrypt message
        encrypted_message = encrypt_message(send_message, self.person_two_pub)
        #person2 decrypt message
        decrypted_message = decrypt_message(encrypted_message, self.person_one_pri, "TeStPaSs1!")
        # make sure the decrypted message is the same as the original message
        self.assertFalse(decrypted_message)
    def test_sign_and_verify(self):
        # create a message to send
        message = 'This is a test!'
        #person1 sign message
        signed_message = encrypt_cleartext_message(message, self.person_one_pri, "TeStPaSs1!")
        #person2 verify sign
        verify_message = vf_msg(signed_message, self.person_one_pub)
        # make sure the signed message is the same as the original message
        self.assertTrue(verify_message)

    def test_sign_with_incorrect_pass(self):
        # create a message to send
        message = 'This is a test!'
        #person1 encrypt message with wrong pass
        signed_message = encrypt_cleartext_message(message, self.person_one_pri, "TeStPaSs2!")
        # make sure the sign fails
        self.assertFalse(signed_message)

    def test_sign_with_not_verified(self):
        # create a message to send
        message = 'This is a test!'
        # person1 encrypt message with wrong pass
        signed_message = encrypt_cleartext_message(message, self.person_one_pri, "TeStPaSs1!")
        #person2 verify sign with wrong public key -simulating not valid
        verify_message = vf_msg(signed_message, self.person_two_pub)
        # make sure the sign fails
        self.assertFalse(verify_message)


if __name__ == '__main__':
    unittest.main()
