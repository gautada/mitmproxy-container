import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

import requests

msg = b'\x18B\x87|p\x94\xf9\xc4\x05\xc2x!\xb45#\x86Z\n\xc0\x85\xa7\x8d\xf3\xf6(K3m\xd8\xa7\x87\xe6\xda@\x00\xf3T!<)\x8cm\xaa\x8d\n\xd8\x01\xf3\xec\x8b\xb6\xd1I9^\x82\x15\xe7\xf7}\xc0\x18\x18\xc8}\xf7\xff-\xa5|\xca\xee\xe0\xe6\xb9\xb2oK\xa5\xaeY\xcb\xa5O\xa0\xbf7\xcce\xab\xa2;vo`*\xff\t\x94\xfa8e\x0e\xdb\x8b\xb7M"\x82[#\xf8\x8aT(\x9b\xbd\x00/)\x9f\xa6\xa2\xf8\x86\xff\x0bp\xc7(\xf7l}:/\n\x8eL=\xfb\xccJ.\x99'

url = 'http://192.168.5.246/stick'
headers = {
'Accept': '*/*',
'Content-Type': 'application/octet-stream',
'Accept-Language': 'en',
'Accept-Encoding': 'gzip, deflate',
'User-Agent': 'RainBird/2.0 CFNetwork/811.5.4 Darwin/16.7.0',
'Connection': 'keep-alive',
'Content-Length': '144',
}
response = requests.request("POST", url, headers=headers, data=msg)
print("Response: %s - %s" % (response.status_code, response.text))
for key, value in response.headers.items():
    print("%s: %s" % (key, value))
print()
print("Envelope:")
print(response.content)



"""

# https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2

# https://stackoverflow.com/questions/46414236/pycrypto-aes-with-password-instead-keyiv
password = 'win-rx-gum-11405'
key = hashlib.sha256(password.encode()).digest()
padding = b'\x00\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

print("AES BLOCK SIZE: %s" % AES.block_size)
print("DIGEST LENGTH: %s" % len(key))

random_bytes = msg[32:48]
encrypted_msg = msg[48:]
iv = msg[:AES.block_size]
cipher = AES.new(key, AES.MODE_CBC, random_bytes)
decrypted = cipher.decrypt(encrypted_msg)
# hash = decrypted[:32]
# h1 = hashlib.sha256(decrypted[32:-len(padding)]).digest()
# h2 = hashlib.sha256(decrypted[32:]).digest()
# decrypted[32:-len(padding)])
print("*****")
print(decrypted)
print(decrypted[:decrypted.find(b'\x00')])
print(hashed_request)
print(hashlib.sha256(decrypted).digest())
print(hashlib.sha256(decrypted[:decrypted.find(b'\x00')]).digest())
print("***")
"""
