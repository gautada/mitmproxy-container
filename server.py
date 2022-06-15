# server.py
import http.server # Our http server handler for http requests
import socketserver # Establish the TCP Socket connections
import urllib
import sys

import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

import requests

PORT = 8000
HASH_LEN = 32
RANDOM_LEN = 16

#  https://gist.github.com/Prakasaka/219fe5695beeb4d6311583e79933a009
# https://www.thepythoncode.com/article/writing-http-proxy-in-python-with-mitmproxy
# https://mitmproxy.org
class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def decrypt(self, envelope):
        # https://medium.com/quick-code/aes-implementation-in-python-a82f582f51c2
        # https://stackoverflow.com/questions/46414236/pycrypto-aes-with-password-instead-keyiv
        password = 'RainBird11405'
        key = hashlib.sha256(password.encode()).digest()
        request_hash = envelope[:HASH_LEN]
        random_bytes = envelope[HASH_LEN:HASH_LEN+RANDOM_LEN]
        encrypted_message = envelope[HASH_LEN+RANDOM_LEN:]
        cipher = AES.new(key, AES.MODE_CBC, random_bytes)
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message[:decrypted_message.find(b'\x00')]
        
    def do_GET(self):
        self.path = 'index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def send_POST(self, envelope):
        url = 'http://192.168.5.246/stick'
        send_headers = {}
        for k, v in self.headers.items():
            if k == 'Host':
                send_headers[k] = '192.168.5.246'
            else:
                send_headers[k] = v
        response = requests.request("POST", url, headers=send_headers, data=envelope)
        print("\033[1;33m")
        print("Response Code: %s" % response.status_code)
        for k, v in response.headers.items():
            print("%s: %s" % (k, v))
        print()
        print()
        print("Response:")
        response.content
        print(response.content)
        print("-------------------------------------------------")
        print(self.decrypt(response.content))
        print("\033[0m")
        return response
        
    def do_POST(self):
        print("\033[1;37m")
        print("Request Line: %s " % self.requestline)
        print("Headers:")
        print(self.headers)
        envelope = self.rfile.read(int(self.headers['Content-Length']))
        print("Envelope:")
        print(envelope)
        print("-------------------------------------------------")
        print(self.decrypt(envelope))
        print("\033[0m")
        response = self.send_POST(envelope)
        self.send_response(response.status_code)
        for k, v in response.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(response.content)
        # return http.server.SimpleHTTPRequestHandler.do_GET(self)
        # self.wfile.write("Lorem Ipsum".encode("utf-8"))

Handler = MyHttpRequestHandler

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    try:
        # httpd.allow_reuse_address = True
        print("Http Server Serving at port", PORT)
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
    except:
        sys.exit(0)


"""

        
        print("*************************************************")
        
        print("*************************************************")
        rqhash = envelope[:32]
        random = envelope[32:48]
        cyphermsg = envelope[48:]
        print("Request Hash: %s" % rqhash)
        print("Random: %s" % random)
        print("Encrypted Messge: %s" % cyphermsg)
        print(length, len(envelope), len(rqhash) + len(random) + len(cyphermsg))
        # assert length == len(rqhash) + len(random) + len(cyphermsg)
        # print(gzip.decompress(data))
        # print(base64.b64decode(data))
        # post_data = urllib.parse.parse_qs(data.decode('utf-8'))
        # You now have a dictionary of the post data
        # print(post_data)
        
        
import os
os.urandom(16)

from hashlib import sha256

input_ = input('Enter something: ')
print(sha256(input_.encode('utf-8')).hexdigest())


  private encrypt(request: Request): Buffer {
    const formattedRequest = this.formatRequest(request);
    const
      passwordHash = crypto.createHash('sha256').update(this.toBytes(this.password)).digest(),
      randomBytes = crypto.randomBytes(16),
      packedRequest = this.toBytes(this.addPadding(`${formattedRequest}\x00\x10`)),
      hashedRequest = crypto.createHash('sha256').update(this.toBytes(formattedRequest)).digest(),
      easEncryptor = new aesjs.ModeOfOperation.cbc(passwordHash, randomBytes),
      encryptedRequest = Buffer.from(easEncryptor.encrypt(packedRequest));
    return Buffer.concat([hashedRequest, randomBytes, encryptedRequest]);
  }

  private decrypt(data: Buffer): string {
    const
      passwordHash = crypto.createHash('sha256').update(this.toBytes(this.password)).digest().slice(0, 32),
      randomBytes = data.slice(32, 48),
      encryptedBody = data.slice(48, data.length),
      aesDecryptor = new aesjs.ModeOfOperation.cbc(passwordHash, randomBytes);
    return new encoder.TextDecoder().decode(aesDecryptor.decrypt(encryptedBody));
  }
"""
    
