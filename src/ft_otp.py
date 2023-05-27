#!/Users/jmorillo/Documents/cyber-camp/.py37env/bin/python

import argparse
import base64
import hmac
import os.path
import random
import re
import string
import struct
import sys
import time
import tkinter as tk
import tkinter.filedialog as tkdialog
import tkinter.ttk as ttk

import PIL.ImageTk
import colorama
import cryptography.fernet
import qrcode


class OtpError(Exception):
    pass


def error_message(message: str) -> str:
    return f'{colorama.Fore.RED}{message}{colorama.Style.RESET_ALL}'


def print_error(message) -> None:
    print(error_message(message))


class Totp:
    OTP_KEY_FILENAME = 'ft_otp.key'

    def __init__(self, interval: int = 30, digits: int = 6, encryption_key: str = None):
        self.__interval = interval
        self.__digits = digits
        self.__encryption_key = encryption_key
        self.__fernet = self.__create_fernet()

    def register_password(self, hex_filepath: str) -> None:
        """
        Read a hexadecimal key of at least 64 characters in file hex_filepath.
        Then, store this key in a file called ft_top.key, which will be encrypted.

        :param hex_filepath: path to the file with the hexidecimal key
        """
        if not os.path.exists(hex_filepath):
            raise OtpError(error_message(f'The file "{hex_filepath}" does not exist.'))
        if not os.access(hex_filepath, os.R_OK):
            raise OtpError(error_message(f'Could not read the file "{hex_filepath}".'))
        with open(hex_filepath) as hex_file:
            hex_password = hex_file.read().lower()
        if re.fullmatch(r'[0-9a-f]{64,}', hex_password) is None:
            raise OtpError(error_message('Key must be at least 64 hexadecimal characters.'))
        self.save_key(hex_password, self.OTP_KEY_FILENAME)

    def generate_new_password(self, key_filepath: str) -> None:
        """
        Generates a new temporary password and print it to standard output

        :param key_filepath: path to the file with the encrypted password
        """
        if not os.path.exists(key_filepath):
            raise OtpError(error_message(f'The file "{key_filepath}" does not exist.'))
        if not os.access(key_filepath, os.R_OK):
            raise OtpError(error_message(f'Could not read the file "{key_filepath}".'))
        with open(key_filepath, 'rb') as key_file:
            key_password = key_file.read()
        try:
            decrypted_password = self.__fernet.decrypt(key_password)
        except cryptography.fernet.InvalidToken:
            raise OtpError(error_message('Invalid encryption password')) from None
        print(self.calc_totp(decrypted_password))

    def save_key(self, hex_password: str, key_filename: str):
        encrypted_password = self.__fernet.encrypt(bytes.fromhex(hex_password))
        with open(key_filename, 'wb') as key_file:
            key_file.write(encrypted_password)

    def calc_totp(self, password: bytes) -> str:
        time_bytes = struct.pack('>Q', int(time.time()) // self.__interval)
        hmac_digest = hmac.digest(password, time_bytes, 'sha1')
        offset = hmac_digest[-1] % 16
        unpack_hash = struct.unpack('>I', hmac_digest[offset:offset + 4])[0]
        truncated_hash = unpack_hash & 0x7fffffff
        return f'{truncated_hash % 10 ** self.__digits:0{self.__digits}}'

    def __create_fernet(self):
        while not self.__encryption_key:
            self.__encryption_key = input('Enter the encryption key: ').strip()[:32]
        self.__encryption_key = f'{self.__encryption_key:_<32}'
        fernet_key = base64.urlsafe_b64encode(self.__encryption_key.encode())
        return cryptography.fernet.Fernet(fernet_key)


class TotpGui:
    PASSWORD_HEX_BASE = tuple(
        map(lambda x: format(ord(x), 'x'), list(string.digits + string.ascii_letters + string.punctuation)))
    DEFAULT_ENCRYPTION = '1234'

    def __init__(self):
        self.tk = tk.Tk()
        self.tk.geometry('600x800')
        self.tk.title('ft_otp')
        self.key_var = tk.StringVar()
        self.key_var.trace('w', self.__key_changed)
        self.hex_file_var = tk.StringVar()
        self.hex_pass_var = tk.StringVar()
        self.hex_pass_var.trace('w', self.__pass_changed)
        self.totp_var = tk.StringVar()
        self.totp = None
        self.qr_img = None
        self.__config()

    def run(self):
        self.tk.after(1000, self.__renew_totp)
        self.tk.mainloop()

    def __config(self):
        self.style = ttk.Style()
        # self.style.theme_use('aqua')
        self.__hex_file_panel()
        self.__key_panel()
        self.__totp_panel()

    def __hex_file_panel(self):
        frame = ttk.LabelFrame(self.tk, text='Hex file', labelanchor=tk.N, relief=tk.FLAT)
        file_frame = ttk.Frame(frame)
        file_label = ttk.Entry(file_frame, textvariable=self.hex_file_var, state='readonly')
        file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.open_button = ttk.Button(file_frame, text='Open', takefocus=False)
        self.open_button.config(command=self.__open_hex)
        self.open_button.pack(side=tk.RIGHT, fill=tk.X, expand=False)
        file_frame.pack(fill=tk.X, expand=True)
        pass_frame = ttk.Frame(frame)
        hex_pass = ttk.Entry(pass_frame, textvariable=self.hex_pass_var, state='readonly')
        hex_pass.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.generate_button = ttk.Button(pass_frame, text='Random generate', takefocus=False)
        self.generate_button.config(command=self.__generate_hex)
        self.generate_button.pack(side=tk.RIGHT, fill=tk.X, expand=False)
        pass_frame.pack(fill=tk.X, expand=True)
        frame.pack(side=tk.TOP, fill=tk.BOTH, expand=False, anchor=tk.N, pady=(0, 20))

    def __key_panel(self):
        frame = ttk.LabelFrame(self.tk, text='Encrypted key', labelanchor=tk.N, relief=tk.FLAT)
        key_entry = ttk.Entry(frame, textvariable=self.key_var, show='*')
        key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.save_button = ttk.Button(frame, text='Save')
        self.save_button.config(command=self.__save_key, state='disabled')
        self.save_button.pack(side=tk.RIGHT, expand=False)
        frame.pack(side=tk.TOP, fill=tk.X, expand=False, anchor=tk.N, pady=(0, 20))

    def __totp_panel(self):
        frame = ttk.LabelFrame(self.tk, text='TOTP', labelanchor=tk.N, relief=tk.FLAT)
        totp_label = ttk.Label(frame, textvariable=self.totp_var, state='readonly')
        totp_label.config(font=('Hack', 32, 'bold'), foreground='#4285f2')
        totp_label.pack(expand=False, anchor='center')
        self.qr_label = ttk.Label(frame, image=self.qr_img)
        self.qr_label.pack(expand=True, anchor='center')
        frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, anchor=tk.N)

    def __key_changed(self, *args):
        value = self.key_var.get()
        if len(value) > 32:
            self.key_var.set(value[:32])
        if not value or not self.hex_pass_var.get():
            self.save_button.config(state='disabled')
        else:
            self.save_button.config(state='enabled')

    def __pass_changed(self, *args):
        value = self.hex_pass_var.get()
        if value:
            self.totp = Totp(encryption_key=self.key_var.get() if self.key_var.get() else self.DEFAULT_ENCRYPTION)
            self.totp_var.set(self.totp.calc_totp(bytes.fromhex(value)))
            self.__generate_qr()
            self.save_button.config(state='enabled' if self.key_var.get() else 'disabled')
        else:
            self.totp = None
            self.totp_var.set('')
            self.qr_img = None
            self.save_button.config(state='disabled')

    def __renew_totp(self):
        if self.totp and self.hex_pass_var.get():
            self.totp_var.set(self.totp.calc_totp(bytes.fromhex(self.hex_pass_var.get())))
        self.tk.after(1000, self.__renew_totp)

    def __open_hex(self):
        hex_filename = self.__open_file()
        self.hex_file_var.set(os.path.split(hex_filename)[1])
        try:
            with open(self.hex_file_var.get()) as hex_file:
                hex_pass = hex_file.read()
                if not re.fullmatch(r'[0-9a-f]{64,}', hex_pass):
                    raise ValueError
                self.hex_pass_var.set(hex_pass)
                self.__generate_qr()
        except (IOError, OSError, ValueError):
            self.hex_pass_var.set('')

    def __generate_hex(self):
        self.hex_file_var.set('')
        hex_list = [random.choice(self.PASSWORD_HEX_BASE) for _ in range(32)]
        hex_txt = ''.join(hex_list)
        self.hex_pass_var.set(hex_txt)

    def __save_key(self):
        filename = self.__save_file()
        if filename:
            self.totp.save_key(self.hex_pass_var.get(), filename)

    def __generate_qr(self):
        password = bytes.fromhex(self.hex_pass_var.get())
        password = base64.b32encode(password).decode()
        self.qr_img = PIL.ImageTk.PhotoImage(qrcode.make(
            f'otpauth://totp/42Malaga:ft_otp_user?secret={password}&issuer=42Malaga'))
        self.qr_label.config(image=self.qr_img)

    def __open_file(self, initial_folder: str = '.') -> str:
        return tkdialog.askopenfilename(parent=self.tk,
                                        title='Select hex file',
                                        initialdir=initial_folder)

    def __save_file(self):
        return tkdialog.asksaveasfilename(parent=self.tk,
                                          title='Save key file',
                                          initialdir='.')


def get_args():
    parser = argparse.ArgumentParser(
        prog='ft_otp',
        description='ft_opt allows you to register an initial password, and generates a new password each time it'
                    ' is requested.',
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-g',
                       type=str,
                       help='Receives a hexadecimal key of at least 64 characters and safely stores this key in'
                            ' a encrypted file called `ft_otp.key`.')
    group.add_argument('-k',
                       type=str,
                       help='Generates a new temporary password and print it to standard output.')
    group.add_argument('-u',
                       action='store_true',
                       help='Launch a graphical interface')
    otp_args = parser.parse_args()
    if not otp_args.g and not otp_args.k and not otp_args.u:
        parser.print_help()
        raise argparse.ArgumentError(None, '')
    return otp_args


if __name__ == '__main__':
    sys.tracebacklimit = 0
    try:
        args = get_args()
    except argparse.ArgumentError as ex:
        print_error(ex.message)
        sys.exit()
    if args.u:
        gui = TotpGui()
        gui.run()
    elif args.g:
        Totp().register_password(args.g)
    elif args.k:
        Totp().generate_new_password(args.k)
