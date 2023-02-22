import os
import pgpy
from pgpy.constants import PubKeyAlgorithm, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, KeyFlags
import pgpy
from pgpy import PGPMessage, PGPKey

from pypgpeed.functions import get_box, make_directory


def make_key(name, email, passphrase, loc):

    make_directory(loc)

    # Generate a new PGP key using the RSAEncryptOrSign algorithm and 4096 bits
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # Create a new user ID for the key using the given name, email, and comment (which is also the name in this case)
    uid = pgpy.PGPUID.new(name, comment=name, email=email)

    # Add the new user ID to the key with the specified usage, hashes, ciphers, and compression settings
    # The key will be used for signing and encrypting communications, as well as encrypting storage
    # The key will use SHA256, SHA384, SHA512, and SHA224 hashes
    # The key will use AES256, AES192, and AES128 ciphers
    # The key will use ZLIB, BZ2, ZIP, and uncompressed compression algorithms
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP,
                             CompressionAlgorithm.Uncompressed])

    # Protect the key with the given passphrase using AES256 encryption and SHA256 hashing
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    # Write the ASCII-armored private key to a file in the given location
    with open(os.path.join(loc, "pri_key.key"), "w") as f:
        f.write(str(key))

    # Write the ASCII-armored public key to a file in the given location
    with open(os.path.join(loc, "pub_key.key"), "w") as f:
        f.write(str(key.pubkey))
    return str(key), str(key.pubkey)


def check_text_and_key(func):
    def wrapper(text="", in_key=None, *args, **kwargs):
        # Find the text box argument, which could be passed as a positional or keyword argument
        box = get_box(text, in_key, *args, **kwargs)

        # Check if the message is empty
        if len(text) == 0:
            # Set the text of the box argument to an error message and return
            box.setText("Message Blank")
            return
        # Check if the key is provided
        if in_key is None or in_key == "":
            # Set the text of the box argument to an error message and return
            box.setText("Key blank - please enter a valid key")
            return
        try:
            # Convert the key from blob format to a PGPKey object
            in_key, _ = PGPKey.from_blob(in_key.strip())
        except ValueError:
            box.setText("Key invalid - please enter a valid key")
            return

        # Call the original function with the given arguments and return its result
        return func(text, in_key, *args, **kwargs)

    return wrapper


def unlock_passphrase(func):
    def wrapper(text="", in_key=None, passphrase=None, *args, **kwargs):
        # Get the text box object
        box = get_box(text, in_key, passphrase, *args, **kwargs)

        # Check if a passphrase was supplied
        if not passphrase or passphrase is None:
            # Set the text of the box object to an error message and return
            box.setText("You have not supplied a passphrase")
            return

        try:
            # Unlock the key with the passphrase
            with in_key.unlock(passphrase):
                # Convert the key from blob format to a PGPKey object
                # in_key = PGPKey.from_blob(in_key.strip())
                # Call the original function with the given arguments and return its result
                return func(text, in_key, passphrase, *args, **kwargs)

        except ValueError:
            if box:
                box.setText("Message not PGP error (possibly plain text)")
            else:
                return False

        except Exception as e:
            # Set the text of the box object to an error message and return
            if box:
                box.setText("Passphrase Error")
            else:
                return False

    return wrapper



@check_text_and_key
def encrypt_message(text, in_key=None, box=None):
    """
    Encrypt a message using a public key.

    Arguments:
    text -- the message to encrypt
    in_key -- the public key used to encrypt the message
    box -- a text box object to display the result (optional)

    Returns:
    The encrypted message as a string, or None if a text box object is provided.
    """
    message = PGPMessage.new(text)
    encrypted = in_key.pubkey.encrypt(message)

    if box:
        box.setText(str(encrypted))
    else:
        return str(encrypted)

@check_text_and_key
@unlock_passphrase
def encrypt_cleartext_message(text="", in_key=None, passphrase=None, box=None):
    """
    Encrypt a cleartext message using a private key and a passphrase.

    Arguments:
    text -- the message to encrypt
    in_key -- the private key used to sign and encrypt the message
    passphrase -- the passphrase to unlock the private key
    box -- a text box object to display the result (optional)

    Returns:
    The encrypted message as a string, or None if a text box object is provided.
    """

    message = PGPMessage.new(text, cleartext=True)
    message |= in_key.sign(message)

    if box:
        box.setText(str(message))
    else:
        return str(message)


@check_text_and_key
@unlock_passphrase
def decrypt_message(text="", in_key=None, passphrase=None, box=None):
    """
    Decrypt a message using a private key and a passphrase.

    Arguments:
    text -- the encrypted message to decrypt
    in_key -- the private key used to decrypt the message
    passphrase -- the passphrase to unlock the private key
    box -- a text box object to display the result (optional)

    Returns:
    The decrypted message as a string, or None if a text box object is provided.
    """
    message = PGPMessage.from_blob(text.strip())
    decrypted = in_key.decrypt(message)

    # sometimes returns a bytearray and not sure why. But this will fix.
    if hasattr(decrypted.message, "decode"):
        message = str(decrypted.message.decode())
    else:
        message = str(decrypted.message)

    if box:
        box.setText(message)
    else:
        return message



@check_text_and_key
def verify_message(text, in_key, box=None):
    """
    Verify a message using a public key.

    Arguments:
    text -- the signed message to verify
    key -- the public key used to verify the message signature

    Returns:
    True if the message signature is valid, False otherwise.
    """
    message = PGPMessage.from_blob(text.strip())
    try:
        key_out = in_key.verify(message)
        if key_out.__bool__():
            box and box.setText("Message verified... It was created by the owner of this public key.")
            return True
    except:
        return False



