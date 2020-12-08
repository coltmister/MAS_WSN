import base64
import datetime
import json
import secrets
import socket

import click
import requests
from flask import Flask, jsonify
from flask import request

from RSA.main import decrypt, encrypt

NODE_ID = 1
E = 65537
IP_ADDRESS = socket.gethostbyname(socket.gethostname())
print("Текущий IP_ADDRESS {IP_ADDRESS}")
BASE_STATION_ADDRESS = "http://127.0.0.1:5000"

with open(f'priv_key{NODE_ID}.txt', 'rb') as f:
    DECODING_KEY = json.loads(base64.b64decode(f.read()))
with open(f'pub_key{NODE_ID}.txt', 'rb') as f:
    ENCODING_KEY = json.loads(base64.b64decode(f.read()))

app = Flask(__name__)


@app.cli.command("send_BS")
@click.argument("payload")
def send_message_to_BS(payload):
    data = {
        "preamble": None,
        "header": encrypt(f"{IP_ADDRESS}|{datetime.datetime.now()}|REPLY".encode("utf-8"), E,
                          ENCODING_KEY['n']),
        "payload": encrypt(payload.encode("utf-8"), E, ENCODING_KEY['n']),
    }
    response = requests.post(BASE_STATION_ADDRESS, json=data)
    print(response.json())


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
        print(request.json)
        data = request.json
        # data = json.loads(request.text)
        if data is None:
            return ErrorResponse('Ошибка при декодировании сообщения')
        if 'preamble' not in data or 'header' not in data or 'payload' not in data:
            return ErrorResponse('Неверный формат сообщения')
        if data['header'] is None:
            return ErrorResponse('Пустой заголовок')
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
        if command == 'REPLY':
            if addr2 != IP_ADDRESS:
                return ErrorResponse('Неверный IP-адрес')
            if data['preamble'] is not None:
                return SuccessResponse("Получение пересланного сообщения прошло успешно")
            else:
                reply_response = {
                    "preamble": IP_ADDRESS,
                    "header": encrypt(
                        f"{IP_ADDRESS}|{datetime.datetime.now().isoformat()}|REPLY-RESPONSE".encode('utf-8'),
                        E,
                        ENCODING_KEY['n']),
                    "payload": encrypt(secrets.token_hex(60).encode('utf-8'), E, ENCODING_KEY['n']),
                }
                return jsonify(reply_response)
        elif command == 'RELAY':
            if 'relay_header' not in data['payload'] or 'relay_payload' not in data['payload']:
                return ErrorResponse('Неверный формата RELAY-сообщения')
            relay_response = {
                "preamble": IP_ADDRESS,
                "header": data['payload']['relay_header'],
                "payload": data['payload']['relay_payload'],
            }
            response = requests.post(addr2, json=relay_response)
            try:
                if response.json()['status'] == 'success':
                    return SuccessResponse("Отправка пересылаемого сообщения прошла успешно")
                else:
                    return ErrorResponse("Отправка пересылаемого сообщения прошла неудачно")
            except KeyError or ValueError:
                return ErrorResponse("Отправка пересылаемого сообщения прошла неудачно")
        elif command == 'GET-DATA':
            pass
        else:
            return ErrorResponse("Неверная команда")
    
    
    
    
    else:
        "None"


if __name__ == '__main__':
    app.run()
