import base64
import datetime
import json
import socket
from backports.datetime_fromisoformat import MonkeyPatch
MonkeyPatch.patch_fromisoformat()
import click
import requests
from flask import Flask, jsonify
from flask import request

from RSA.main import decrypt, encrypt

E = 65537
IP_ADDRESS = f"http://{socket.gethostbyname(socket.gethostname())}:5000"
print(f"Текущий IP_ADDRESS {IP_ADDRESS}")

# with open(f'priv_key{NODE_ID}.txt', 'rb') as f:
#     DECODING_KEY = json.loads(base64.b64decode(f.read()))
# with open(f'pub_key{NODE_ID}.txt', 'rb') as f:
#     ENCODING_KEY = json.loads(base64.b64decode(f.read()))
NODES = [
    {'id': 1, "self": True, "address": "http://10.132.15.43:5000"},
    {'id': 2, "self": False, "address": "http://10.132.15.125:5000", "relay": 'http://10.132.15.125:5000'},
]

app = Flask(__name__)


@app.cli.command("send_node")
@click.option('--command', default="REPLY", help='What does you want to send to the node REPLY/GET-DATA')
@click.option('--node_id', default="1", help='Which node to send?')
def send_message_to_node(command, node_id):
    NODE = None
    for node in NODES:
        if node['id'] == int(node_id):
            NODE = node
            break
    
    if NODE is None:
        print("Данный узел не найден")
        exit(0)
    else:
        with open(f'priv_key{NODE["id"]}.txt', 'rb') as f:
            DECODING_KEY = json.loads(base64.b64decode(f.read()))
        with open(f'pub_key{NODE["id"]}.txt', 'rb') as f:
            ENCODING_KEY = json.loads(base64.b64decode(f.read()))
        if not NODE['self']:
            data = {
                "preamble": None,
                "header": encrypt(f"{NODE['relay']}|{datetime.datetime.now()}|RELAY".encode("utf-8"), E,
                                  ENCODING_KEY['n']),
                "payload": {
                    "relay_header": encrypt(
                        f"{NODE['address']}|{datetime.datetime.now()}|{command}".encode("utf-8"), E,
                        ENCODING_KEY['n']),
                    "relay_payload": None,
                }
            }
            requests.post(NODE['relay'], json=data)
        else:
            data = {
                "preamble": None,
                "header": encrypt(f"{NODE['address']}|{datetime.datetime.now()}|{command}".encode("utf-8"), E,
                                  ENCODING_KEY['n']),
                "payload": None,
            }
            requests.post(NODE['address'], json=data)


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
        try:
            NODE = None
            for node in NODES:
                if data['preamble'] in node['address']:
                    NODE = node
                    break
            if NODE is None:
                return ErrorResponse('Данный узел не найден')
            with open(f'priv_key{NODE["id"]}.txt', 'rb') as f:
                DECODING_KEY = json.loads(base64.b64decode(f.read()))
            with open(f'pub_key{NODE["id"]}.txt', 'rb') as f:
                ENCODING_KEY = json.loads(base64.b64decode(f.read()))
            decrypted_header = decrypt(data['header'], E, DECODING_KEY['p'], DECODING_KEY['q'])
        except ValueError:
            return ErrorResponse('Не удалось расшифровать')
        try:
            addr2, nonce, command = decrypted_header.split('|')
        except ValueError:
            return ErrorResponse('Неверный формат заголовка')
        if (datetime.datetime.fromisoformat(nonce) + datetime.timedelta(minutes=1)) < datetime.datetime.now():
            return ErrorResponse('Старый запрос. Возможно попытка отправить старое сообщение')
        elif command == 'SEND-DATA':
            try:
                decrypted_payload = decrypt(data['payload'], E, DECODING_KEY['p'], DECODING_KEY['q'])
            except (ValueError, KeyError):
                print("ОШИБКА")
            try:
                addr2, nonce, command = decrypted_header.split('|')
                print("Ответ:", addr2, nonce, command)
                print("Данные:", decrypted_payload)
                return SuccessResponse("Получение сообщения прошло успешно")
            except (ValueError, KeyError):
                # print(response.text)
                return ErrorResponse("Неверный формат сообщения")
        else:
            return ErrorResponse("Неверная команда")
    else:
        return ErrorResponse('Неверный метод')


if __name__ == '__main__':
    app.run(host='10.132.15.56', port=5000, threaded=True)
