import kryptool
import time
from colorama import init, Fore, Style


def colors():
    init(autoreset=True)
    global cyan
    cyan = Style.BRIGHT + Fore.CYAN
    global red
    red = Style.BRIGHT + Fore.RED
    global green
    green = Style.BRIGHT + Fore.GREEN
    global white
    white = Style.BRIGHT + Fore.WHITE


colors()

# example demonstration of Krypto encrypting 100 server/pass combinations
example_encrypt = kryptool.Kryptool(csv_file='passlist.csv',
                                    key_password_name="K3yP@ss",
                                    encrypt_filename='$ecret3ncrypt3dFil3',
                                    salt_filename='$ecret$alt')

# example demonstration of Krypto dencrypting 100 server/pass combinations
example_decrypt = kryptool.Kryptool(decrypt_filename='$ecret3ncrypt3dFil3',
                                    salt_filename='$ecret$alt',
                                    key_password_name='K3yP@ss')

example_bad_salt_password = kryptool.Kryptool(decrypt_filename='$ecret3ncrypt3dFil3',
                                              salt_filename='$ecret$alt',
                                              key_password_name='badK3yP@ss')


if __name__ == '__main__':
    start = time.time()
    print()
    print(cyan + 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
                 ' Starting Kryptool Encryption Example  '
                 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print()
    example_encrypt.data_hasher()
    print(green + 'job execution time:', time.time() - start)
    print('\n' * 3)
    start = time.time()
    print(cyan + 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
                 ' Starting Kryptool Decryption Example  '
                 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print()
    example_decrypt.data_decrypt()
    print()
    print(green + 'Job execution time:', time.time() - start)
    print()
    print('\n' * 3)
    print(cyan + 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
                 ' Starting Kryptool Bad Salt Password Example  '
                 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
    print()
    start = time.time()
    example_bad_salt_password.data_decrypt()
    print(red + 'Job execution time:', time.time() - start)
    print()

