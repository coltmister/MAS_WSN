import base64
import datetime
import json

import requests

from RSA.main import encrypt, decrypt

NODE_ID = 1
E = 65537
with open(f'priv_key{NODE_ID}.txt', 'rb') as f:
    DECODING_KEY = json.loads(base64.b64decode(f.read()))
    print(DECODING_KEY)
with open(f'pub_key{NODE_ID}.txt', 'rb') as f:
    ENCODING_KEY = json.loads(base64.b64decode(f.read()))
    print(ENCODING_KEY)

# data = {
#     "preamble": None,
#     "header": encrypt(f"http://127.0.0.1:5000|{datetime.datetime.now()}|REPLY".encode("utf-8"), E,
#                       ENCODING_KEY['n']),
#     "payload": "kek"
# }
data = {
    "preamble": "192.168.31.244",
    "header": encrypt(f"http://127.0.0.1:5000|{datetime.datetime.now()}|RELAY".encode("utf-8"), E,
                      ENCODING_KEY['n']),
    "payload": {
        "relay_header": encrypt(f"192.168.31.244|{datetime.datetime.now()}|REPLY".encode("utf-8"), E,
                                ENCODING_KEY['n']),
        "relay_payload": 'kek'
    }
}
response = requests.post('http://127.0.0.1:5000', json=data)
data = response.json()

try:
    decrypted_header = decrypt(data['header'], E, DECODING_KEY['p'], DECODING_KEY['q'])
    decrypted_payload = decrypt(data['payload'], E, DECODING_KEY['p'], DECODING_KEY['q'])
except (ValueError, KeyError):
    print(response.text)
    exit()
try:
    addr2, nonce, command = decrypted_header.split('/')
    print(addr2, nonce, command)
    print(decrypted_payload)
except (ValueError, KeyError):
    print(response.text)
