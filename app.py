from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time
app = Flask(__name__)
jwt_token = None
jwt_lock = threading.Lock()
def extract_token_from_response(data, region):
    """
    Função universal e mais robusta para extrair o token da re.
    """
    # 1. Verifica se a resposta é um dicionário e se a chave 'token' existe.
    if not isinstance(data, dict) or 'token' not in data:
        print(f"[{region}] Resposta da API de token é inválida ou não contém a chave 'token'. Resposta: {data}")
        return None

    # 2. Verifica o campo 'status', se ele existir.
    #    Aceita 'success' ou 'live' como status válidos.
    if 'status' in data and data['status'] not in ['success', 'live']:
        print(f"[{region}] Status da API de token não é válido. Status: {data.get('status')}")
        return None
    
    # 3. Se todas as verificações passaram, retorna o token.
    return data.get('token')
def get_jwt_token_sync(region):
    global jwt_token
    endpoints = {  # https://jwt-info-api-production.up.railway.app/create_jwt?uid=3923823977&password=CA6E4DCC24A1E822147CB05A1F38DD40934AA77176C950FBA153ECA8F70DA2E4
        "IND": "https://jwtgenchx.vercel.app:8000/token?uid=3976277520&password=3C07CA0CF3C22DB4DB5A00A8C75E3FED7869FB11CED0ADFB5C8DE7E92652B704",
        "BR": "http://jwt.thug4ff.com/token?uid=3923823977&password=CA6E4DCC24A1E822147CB05A1F38DD40934AA77176C950FBA153ECA8F70DA2E4",
        "US": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "SAC": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "NA": "https://tokenalljwt.onrender.com/api/oauth_guest?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39lH3x2kJkO",
        "default": "http://jwt.thug4ff.com/token?uid=3923823977&password=CA6E4DCC24A1E822147CB05A1F38DD40934AA77176C950FBA153ECA8F70DA2E4"
    }    
    url = endpoints.get(region, endpoints["default"])
    with jwt_lock:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                token = extract_token_from_response(data, region)
                if token:
                    jwt_token = token
                    print(f"JWT Token for {region} updated successfully: {token[:50]}...")
                    return jwt_token
                else:
                    print(f"Failed to extract token from response for {region}")
            else:
                print(f"Failed to get JWT token for {region}: HTTP {response.status_code}")
        except Exception as e:
            print(f"Request error for {region}: {e}")   
    return None
def ensure_jwt_token_sync(region):
    global jwt_token
    if not jwt_token:
        print(f"JWT token for {region} is missing. Attempting to fetch a new one...")
        return get_jwt_token_sync(region)
    return jwt_token
def jwt_token_updater(region):
    while True:
        get_jwt_token_sync(region)
        time.sleep(300)
def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"
def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()
def apis(idd, region):
    global jwt_token    
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")    
    endpoint = get_api_endpoint(region)    
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Accept-Encoding': "gzip",
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB48',
        'Content-Type': 'application/x-www-form-urlencoded',
    }   
    try:
        data = bytes.fromhex(idd)
        response = requests.post(
            endpoint,
            headers=headers,
            data=data,
            timeout=10
        )
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"API request to {endpoint} failed: {e}")
        raise
@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'BR').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        threading.Thread(target=jwt_token_updater, args=(region,), daemon=True).start()
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response = apis(encrypted_hex, region) 
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response)) 
        result = MessageToDict(message)
        result['Owners'] = ['TeamxCutehack!!']
        return jsonify(result)
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"Error processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500
@app.route('/favicon.ico')
def favicon():
    return '', 404
if __name__ == "__main__":
    ensure_jwt_token_sync("BR")
    app.run(host="0.0.0.0", port=5552)
