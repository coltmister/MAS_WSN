import base64
import json

from RSA.main import generateKeys

# print(f"Закрытая пара d|n: {d}|{n}")
# print(f"Открытая пара e|n: {e}|{n}")

for i in range(5):
    e, d, n, p, q = generateKeys()
    with open(f'priv_key{i}.txt', 'wb') as f:
        temp = base64.b64encode(json.dumps({
            "d": d,
            "n": n,
            "p": p,
            "q": q
        }).encode('utf-8'))
        f.write(temp)
    with open(f'pub_key{i}.txt', 'wb') as f:
        temp = base64.b64encode(json.dumps({"n": n,
                                            "p": p,
                                            "q": q}).encode('utf-8'))
        f.write(temp)
