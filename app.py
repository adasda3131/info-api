from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
import os
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time

app = Flask(__name__)

# --- Gerenciamento de Token ---
jwt_token = None
jwt_lock = threading.Lock()

def extract_token_from_response(data, region):
    if not isinstance(data, dict):
        print(f"[{region}] Resposta da API de token não é um JSON válido. Resposta: {data}")
        return None
    # Adapte para a resposta da SUA API
    token = data.get('token')
    status = data.get('status')
    if token and status == 'live':
        return token
    print(f"[{region}] Resposta da API de token é inválida. Token: {token}, Status: {status}")
    return None

def get_jwt_token_sync(region):
    global jwt_token
    
    # <<< MUDANÇA CRÍTICA: Use sua própria API de JWT que está no Railway!
    # Substitua a URL abaixo pela URL real da sua outra aplicação no Railway.
    SUA_API_JWT_URL = "http://jwt.thug4ff.com" # /token?
    
    endpoints = {
        "BR": f"{SUA_API_JWT_URL}/create_jwt?uid=3923823977&password=CA6E4DCC24A1E822147CB05A1F38DD40934AA77176C950FBA153ECA8F70DA2E4",
        # Adicione outras regiões se necessário, apontando para sua API
    }
    
    url = endpoints.get(region, endpoints["BR"]) # Padrão para BR se a região não for encontrada
    
    # O lock garante que apenas uma thread atualize o token por vez
    with jwt_lock:
        try:
            response = requests.get(url, timeout=15) # Aumentei o timeout
            if response.status_code == 200:
                data = response.json()
                token = extract_token_from_response(data, region)
                if token:
                    jwt_token = token
                    print(f"JWT Token para {region} atualizado com SUCESSO.")
                    return jwt_token
                else:
                    print(f"Falha ao extrair token da resposta para {region}")
            else:
                print(f"Falha ao obter token JWT para {region}: HTTP {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Erro na requisição para obter token JWT para {region}: {e}")   
    return None

def ensure_jwt_token_sync(region):
    # Se o token não existe, busca um novo
    if not jwt_token:
        print(f"Token JWT para {region} está faltando. Buscando um novo...")
        return get_jwt_token_sync(region)
    return jwt_token

def jwt_token_updater(region):
    print("-> Thread de atualização de token iniciada.")
    while True:
        print("-> Atualizando token JWT em segundo plano...")
        get_jwt_token_sync(region)
        # Atualiza a cada 5 minutos
        time.sleep(300)

# --- Lógica da API (praticamente sem mudanças) ---
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
    # <<< MUDANÇA: Se o token falhar, tenta buscar um novo e refazer a chamada UMA VEZ.
    # Isso torna a API "auto-corrigível" se o token expirar.
    for attempt in range(2):
        token = ensure_jwt_token_sync(region)
        if not token:
            return jsonify({"error": f"Não foi possível obter um token JWT válido para a região {region}"}), 503

        endpoint = get_api_endpoint(region)    
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/octet-stream', # Alterado para o tipo correto
        }
        
        try:
            data = bytes.fromhex(idd)
            response = requests.post(endpoint, headers=headers, data=data, timeout=10)
            
            if response.status_code == 401 and attempt == 0:
                print("Token inválido (401). Forçando a busca por um novo token e tentando novamente...")
                get_jwt_token_sync(region) # Força a atualização
                continue # Tenta novamente no loop
            
            response.raise_for_status()
            return response.content.hex()
            
        except requests.exceptions.RequestException as e:
            print(f"Falha na requisição da API para {endpoint}: {e}")
            raise
    
    # Se chegou aqui, as duas tentativas falharam
    raise Exception("Falha ao processar a requisição após nova tentativa com novo token.")

@app.route("/")
def health_check():
    return jsonify({"status": "ok"})

@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'BR').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)

        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        api_response = apis(encrypted_hex, region) 
        
        if not api_response:
            return jsonify({"error": "Resposta vazia da API da Garena"}), 500
            
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response)) 
        result = MessageToDict(message)
        
        result['Owners'] = ['erick fodao']
        return jsonify(result)

    except ValueError:
        return jsonify({"error": "Formato de UID inválido"}), 400
    except Exception as e:
        print(f"Erro ao processar a requisição: {e}")
        return jsonify({"error": f"Falha ao processar os dados: {str(e)}"}), 500

if __name__ == "__main__":
    # Define a região padrão para a aplicação
    DEFAULT_REGION = "BR"
    
    # Busca o token inicial ao iniciar
    ensure_jwt_token_sync(DEFAULT_REGION)
    
    # <<< MUDANÇA CRÍTICA: Inicia a thread de atualização APENAS UMA VEZ
    updater_thread = threading.Thread(target=jwt_token_updater, args=(DEFAULT_REGION,), daemon=True)
    updater_thread.start()
    
    # Inicia o servidor Flask
    port = int(os.environ.get("PORT", 5552))
    app.run(host="0.0.0.0", port=port)
