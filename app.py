import base64
import datetime
import json
import secrets
import socket
from backports.datetime_fromisoformat import MonkeyPatch
MonkeyPatch.patch_fromisoformat()
import requests
from flask import Flask, jsonify
from flask import request

from RSA.main import decrypt, encrypt

NODE_ID = 2
# RELAY_NODE = "http://10.132.15.125:5000"
RELAY_NODE = None
E = 65537
#IP_ADDRESS = f"http://{socket.gethostbyname(socket.gethostname())}:5000"
IP_ADDRESS="http://192.168.31.74:5000"
print(f"Текущий IP_ADDRESS {IP_ADDRESS}")
BASE_STATION_ADDRESS = "http://192.168.31.245:5000"

with open(f'priv_key{NODE_ID}.txt', 'rb') as f:
    DECODING_KEY = json.loads(base64.b64decode(f.read()))
with open(f'pub_key{NODE_ID}.txt', 'rb') as f:
    ENCODING_KEY = json.loads(base64.b64decode(f.read()))

app = Flask(__name__)


@app.cli.command("send_BS")
def send_message_to_BS():
    if RELAY_NODE is not None:
        data = {
            "preamble": IP_ADDRESS,
            "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|RELAY".encode("utf-8"), E,
                              ENCODING_KEY['n']),
            "payload": {
                "relay_header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|SEND-DATA".encode("utf-8"), E,
                                        ENCODING_KEY['n']),
                "relay_payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
            }
        }
        requests.post(RELAY_NODE, json=data)
    else:
        data = {
            "preamble": IP_ADDRESS,
            "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|SEND-DATA".encode("utf-8"), E,
                              ENCODING_KEY['n']),
            "payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
        }
        requests.post(BASE_STATION_ADDRESS, json=data)


"""
{
"preamble": "ADDR1/None",
"header:"ENCODED", // ADDR2/DTG/COMMAND
"payload": "ENCODED"// DATA
}
"""


def ErrorResponse(message):
    print(message)
    return jsonify({"status": 'error', "message": message})


def SuccessResponse(text):
    print(text)
    reply_response = {
        "status": "success",
        "message": 'OK'
    }
    return jsonify(reply_response)


@app.route('/', methods=['GET', 'POST'])
def reply():
    if request.method == 'POST':
        data = request.json
        # data = json.loads(request.text)
        if data is None:
            return ErrorResponse('Ошибка при декодировании сообщения')
        if 'preamble' not in data or 'header' not in data or 'payload' not in data:
            return ErrorResponse('Неверный формат сообщения')
        if data['header'] is None:
            return ErrorResponse('Пустой заголовок')
        if data['preamble'] is None:
            try:
                decrypted_header = decrypt(data['header'], E, DECODING_KEY['p'], DECODING_KEY['q'])
            except ValueError:
                return ErrorResponse('Не удалось расшифровать')
            try:
                addr2, nonce, command = decrypted_header.split('|')
            except ValueError:
                return ErrorResponse('Неверный формат заголовка')
            if (datetime.datetime.fromisoformat(nonce) + datetime.timedelta(minutes=1)) < datetime.datetime.now():
                return ErrorResponse('Старый запрос. Возможно попытка отправить старое сообщение')
        else:
            if 'relay_header' not in data['payload'] or 'relay_payload' not in data['payload']:
                return ErrorResponse('Неверный формата RELAY-сообщения')
            relay_response = {
                "preamble": data['preamble'],
                "header": data['payload']['relay_header'],
                "payload": data['payload']['relay_payload'],
            }
            response = requests.post(BASE_STATION_ADDRESS, json=relay_response)
            print(response.text)
            try:
                if response.json()['status'] == 'success':
                    return SuccessResponse("Отправка пересылаемого сообщения прошла успешно")
                else:
                    return ErrorResponse("Отправка пересылаемого сообщения прошла неудачно")
            except KeyError or ValueError:
                return ErrorResponse("Отправка пересылаемого сообщения прошла неудачно")
        if command == 'REPLY':
            if addr2 != IP_ADDRESS:
                return ErrorResponse('Неверный IP-адрес')
            if data['preamble'] is not None:
                return SuccessResponse("Получение пересланного сообщения прошло успешно")
            else:
                if RELAY_NODE is not None:
                    data = {
                        "preamble": IP_ADDRESS,
                        "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|RELAY".encode("utf-8"), E,
                                          ENCODING_KEY['n']),
                        "payload": {
                            "relay_header": encrypt(
                                f"{IP_ADDRESS}|{datetime.datetime.now().isoformat()}|REPLY-RESPONSE".encode('utf-8'),
                                E,
                                ENCODING_KEY['n']),
                            "relay_payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
                        }
                    }
                    requests.post(RELAY_NODE, json=data)
                else:
                    data = {
                        "preamble": IP_ADDRESS,
                        "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|REPLY-RESPONSE".encode("utf-8"), E,
                                          ENCODING_KEY['n']),
                        "payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
                    }
                    requests.post(BASE_STATION_ADDRESS, json=data)
                return SuccessResponse("Отправка ответного сообщения прошла успешно")
        elif command == 'GET-DATA':
            print("Полученная команда:", addr2, nonce, command)
            if RELAY_NODE is not None:
                data = {
                    "preamble": IP_ADDRESS,
                    "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|RELAY".encode("utf-8"), E,
                                      ENCODING_KEY['n']),
                    "payload": {
                        "relay_header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|SEND-DATA".encode("utf-8"), E,
                                                ENCODING_KEY['n']),
                        "relay_payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
                    }
                }
                requests.post(RELAY_NODE, json=data)
            else:
                data = {
                    "preamble": IP_ADDRESS,
                    "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|SEND-DATA".encode("utf-8"), E,
                                      ENCODING_KEY['n']),
                    "payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
                }
                requests.post(BASE_STATION_ADDRESS, json=data)
            return SuccessResponse("Отправка ответного сообщения прошла успешно")
    else:
        return ErrorResponse('Неверный метод')


if __name__ == '__main__':
    app.run(host='192.168.31.74', port=5000, threaded=True)
