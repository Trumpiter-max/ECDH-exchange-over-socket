"""
A point in the group and the order of the group (in this case the number of points on the elliptic curve) are public knowledge.

Bob chooses a secret message (a number b with 0 < b < n).
Alice chooses a secret message (a number a with 0 < a < n).

"""

from random import SystemRandom
from Elliptic_Curve import EllipticCurve
try:
	from Crypto.Cipher import AES
except ModuleNotFoundError:
	print("You need to install pycryptodome")
	exit(1)
import hashlib
rand=SystemRandom()
def hashit(str):
	"""
	Returns the digest of the SHA-256 hash function for use as the key in our AES-256 encryption.
	"""
	result = hashlib.sha256(str.encode())
	return result.digest()

def encrypt(message, exchanged_value):
	"""
	Encrypts the message using the symmetric encryption scheme AES-256 with x-coordinate of the shared secret as a key.
	"""
	data = message.encode("utf8")
	key = hashit(exchanged_value)
	cipher = AES.new(key,AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext,tag = cipher.encrypt_and_digest(data)
	return(nonce,ciphertext,tag)


def decrypt(encrypted, exchanged_value):
	"""
	Decrypting the message. The variable "encrypted" is a tuple (nonce,ciphertext,tag).
	Since bob has the shared secret, he can make the appropriate key.
	For an attacker to (naively) obtain the correct key, they must solve the ECDLP.
	"""
	key = hashit(exchanged_value)
	cipher = AES.new(key,AES.MODE_EAX, nonce = encrypted[0])
	plaintext = cipher.decrypt(encrypted[1])
	try:
		cipher.verify(encrypted[2])
	except ValueError:
		print("The message could not be verified!")
	return plaintext.decode("utf8")
