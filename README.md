# Gnu-ransom
Python ransomware for prevention and awareness purposes

[![Available](https://img.shields.io/badge/Target-Gnu/Linux-blue.svg?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-GPL%20v3%2B-red.svg?style=for-the-badge)](https://github.com/hacknonym/Gnu-ransom/blob/master/LICENSE)

### Author: github.com/hacknonym

## A GNU/Linux Prevention Ransomware

## Legal disclaimer

Usage of **Gnu-ransom** for attacking targets without prior mutual consent is illegal.
Do not use in military or secret service organizations, or for illegal purposes.
It's the end user's responsibility to obey all applicable local, state and federal laws. 
Developer assume no liability and is not responsible for any misuse or damage caused by this program.

## Security
- For reasons of **prevention** and **awareness**, the use of the program is planned locally only 
- The `--verbose` option is enabled by default without disabling 
- The `--quiet` option is not present, the progress of the program must be done manually during execution
- For reasons of concealment of the code, no modular programming has been made
- The malicious code is not obfused
- The malicious code is not compiled
- The malicious code depends on several dependencies (a real case will involve a local implementation of the dependencies, for reasons of compatibility and attack surface) 

## Features !
- Define the target locations to encrypt
- Define an extension for encrypted files (default .cry)
- Change the wallpaper with a personalized
- Define the extensions to encrypt (jpg, docx, etc.)
- Using the AES-256 bit EAX symmetrical encryption algorithm for file encryption
- Using the RSA-4096 bit asymmetric encryption algorithm for encryption of information sent to the attacker's server
- Using the SSL/TLS Transport Protocol for Encryption of Server Client Communications at HTTP
- The X509 certificate is signed with an RSA-4096 bits key
> If the validity period of the certificate has elapsed
```bash
# Generate x509 certificate for 'localhost' domain name
$ openssl req -x509 -out server.crt -keyout server.key -newkey rsa:4096 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config <(printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
$ cat server.crt server.key > server.pem
```

## Prerequisites
- GNU/Linux environnement
- The victim system must benefit from the `python3` interpreter
```bash
sudo apt update && sudo apt install -y python3 python3-pip
```

## Installation
```bash
git clone https://github.com/hacknonym/Gnu-ransom.git
cd Gnu-ransom
chmod u+x *.py
pip3 install -r requirements.txt
```

# Usage
```bash
# Start HTTPS Server
./server.py
# Start the ransomware
./ransom.py --directory /home/username/workgroup,/root,/media --format pdf,docx,xlsx,txt,jpeg
# Start the decryptor
./decryptor.py --directory /home/username/workgroup,/root,/media --key [AES_KEY]
```

# Demo
[Full demo Video (3min)](https://streamable.com/f0nmfl)

## License
GNU General Public License v3.0 for Gnu-ransom
AUTHOR: @hacknonym
