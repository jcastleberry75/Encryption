#!/usr/bin/python3

__author__ = "Jay Castleberry - jcastleberry75@outlook.com"
__version__ = "1.0.0"
__license__ = "MIT"

# Kryptool converts a plain text, two column  csv file of user/pass or node/pass combinations
# and encrypts them into a single pickle file hashed via SHA-512

import os
import pickle
import csv
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
from colorama import init, Fore, Style


class Kryptool:

    def __init__(self,
                 csv_file=None,
                 key_password_name=None,
                 encrypt_filename=None,
                 decrypt_filename=None,
                 salt_filename=None):

        self.csv_file = csv_file
        self.key_password_name = key_password_name
        self.encrypt_filename = encrypt_filename
        self.decrypt_filename = decrypt_filename
        self.salt_name = salt_filename

    def colors(self):
        init(autoreset=True)
        global cyan
        cyan = Style.BRIGHT + Fore.CYAN
        global red
        red = Style.BRIGHT + Fore.RED
        global green
        green = Style.BRIGHT + Fore.GREEN
        global white
        white = Style.BRIGHT + Fore.WHITE

    @property
    def csv_dict_converter(self):
        self.colors()
        # converts csv file data to a dictionary object
        data_keys = {}
        try:
            with open(self.csv_file, 'r', newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    data_keys[row[0]] = row[1]
            print('The following dictionary was parsed from the csv input file...' + '\n')
        except NameError:
            print("File Name not found.")
        except IOError as e:
            errno, strerror = e.args
            print(red + "I/O error({0}): {1}".format(errno, strerror))

        else:
            print(data_keys)

            return data_keys

    def pickle_reader(self, file_to_read=None):
        self.colors()
        print('Starting pickle file read for ' + str(file_to_read) + '\n')
        try:
            with open(file_to_read, 'rb') as pickle_file:
                pickle_data = pickle.load(pickle_file)
                return pickle_data

        except IOError as e:
            errno, strerror = e.args
            print(red + "I/O error({0}): {1}".format(errno, strerror))

    def pickle_writer(self, data_to_write, name_for_file):
        print('Starting pickle file write for ' + str(name_for_file) +  '\n')
        # pickles a data object, names per argument, writes to pickle file
        current_dir = os.path.abspath('')
        print('Pickle Data will be written to the following path...')
        print(current_dir + '\n')
        try:
            with open(current_dir + '/' + name_for_file, 'wb') as p:
                pickle.dump(data_to_write, p)
        except IOError as e:
            errno, strerror = e.args
            print(red + "I/O error({0}): {1}".format(errno, strerror))

    def data_hasher(self):
        self.colors()
        data = self.csv_dict_converter
        # Creates Salt and encrypts dictionary
        dict_json = json.dumps(data)
        binary_data = dict_json.encode()
        print("The Dictionary has been converted to binary data...")
        salt_data = os.urandom(32)
        self.pickle_writer(salt_data, self.salt_name)
        print("The following random Salt has been generated: " + white + str(salt_data))
        print()
        print('Encrypting The CSV Data...')
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(),
                         length=32,
                         salt=salt_data,
                         iterations=1000000,
                         backend=default_backend())
        bin_key_password_name = self.key_password_name.encode()
        key = base64.urlsafe_b64encode(kdf.derive(bin_key_password_name))
        print('The Salt Has been added to the CSV Data and it is now hashing '
              'via 1,000,000 iterations of the SHA512 Algorithm:')
        f = Fernet(key)
        encrypted_data = f.encrypt(binary_data)
        try:
            self.pickle_writer(encrypted_data, self.encrypt_filename)
            print(green + 'XXXXXXXXXXXXXXXXXXXXXX')
            print(green + 'Encryption Successful!')
            print(green + 'XXXXXXXXXXXXXXXXXXXXXX')
            print()
        except IOError as e:
            errno, strerror = e.args
            print(red + "I/O error({0}): {1}".format(errno, strerror))

    def data_decrypt(self):
        self.colors()
        salt_data = self.pickle_reader(self.salt_name)

        def salt_verify():
            if salt_data is None:
                print(red + 'XXXXXXXXXXXXXXXXXXXXXXX')
                print(red + 'Bad Salt File..Exiting!')
                print(red + 'XXXXXXXXXXXXXXXXXXXXXXX')
        salt_verify()
        try:
            dict_data = self.pickle_reader(self.decrypt_filename)
            print('Decrypting The Dictionary...')
            print()
            salt_data = self.pickle_reader(self.salt_name)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt_data,
                             iterations=1000000, backend=default_backend())
            binary_password_str = self.key_password_name.encode()
            key = base64.urlsafe_b64encode(kdf.derive(binary_password_str))
            f = Fernet(key)
            decrypted_dict_binary_data = f.decrypt(dict_data)
            decoded_bin_data = decrypted_dict_binary_data.decode()
            json_dict = json.loads(decoded_bin_data)
        except InvalidToken:
            print()
            print(red + 'XXXXXXXXXXXXXXXXXXXXXXXXXX')
            print(red + 'Invalid Salt Key Password!')
            print(red + 'XXXXXXXXXXXXXXXXXXXXXXXXXX')
            print()
        else:
            print(green + 'XXXXXXXXXXXXXXXXXXXXXX')
            print(green + 'Decryption Successful!')
            print(green + 'XXXXXXXXXXXXXXXXXXXXXX')
            print()
            print(json_dict)
            return json_dict
