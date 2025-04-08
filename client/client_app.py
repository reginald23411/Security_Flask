from flask import Flask, request, redirect, url_for,Response, session, jsonify
import requests
import hmac
import hashlib
import secrets
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import io 
from flask import send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend

# create secret key if not exist
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_FILE = os.path.join(BASE_DIR, "secret.key")
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, "rb") as f:
        secret_key = f.read()
else:
    secret_key = secrets.token_bytes(32)
    with open(SECRET_KEY_FILE, "wb") as f:
        f.write(secret_key)

Client = Flask(__name__)
# load secret key for program use
Client.secret_key = secret_key

SERVER_API_BASE = 'http://127.0.0.1:5000/api'

# PKC: create public key and private key in register stage and PK for shared file AES-key encryption, SK for shared file AES-key decryption
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public


def retrieve_private_key(username):
    # Determine the base directory (same as in your code)
    client_dir = os.path.dirname(__file__)

    # Construct the directory and file path
    user_key_dir = os.path.join(client_dir, "PKC_KEY", f"{username}_keys")
    SK_file_name = f"{username}_private_key.pem"
    file_path = os.path.join(user_key_dir, SK_file_name)

    # Check if the file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Private key file not found at: {file_path}")

    # Read the private key content
    with open(file_path, "rb") as f:
        private_key_content = f.read()

    return private_key_content

#------------get page from server ---------------
@Client.route('/')
def to_login_page():
    resp = requests.get(f"{SERVER_API_BASE}/page/")
    return Response(resp.text, mimetype='text/html')

@Client.route('/driver')
def to_driver_page():
    if 'user_id' not in session:
        return redirect(url_for('to_login_page'))
    
    user_id = session.get('user_id')
    
    # 獲取頁面
    resp = requests.get(f"{SERVER_API_BASE}/page/driver")
    html_content = resp.text
    
    # 手動替換模板變數
    modified_html = html_content.replace('const userId = "{{ user_id }}";', f'const userId = "{user_id}";')
    
    return Response(modified_html, mimetype='text/html')
#----------------------------------------------------

def hash_password(password: str,salt=None) -> str:
    if salt==None:
        # PRNG
        salt = secrets.token_bytes(16)
    # PRNG value from local file and flask config
    key = Client.secret_key

    # store digest and password in hex
    hex_digest= hmac.new(key, password.encode('utf-8') + salt, hashlib.sha256).hexdigest()
    return hex_digest,salt.hex()

def get_salt_for_user(username):
    response = requests.get(f"{SERVER_API_BASE}/get_salt/{username}")
    if response.status_code == 200:
        salt_hex = response.json().get("salt")
        return bytes.fromhex(salt_hex)
    else:
        print(response.json().get("error"))
        return None

# for html action
@Client.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    salt = get_salt_for_user(username)
    hashed_password = hash_password(password,salt)[0]

    response = requests.post(f'{SERVER_API_BASE}/login', json={
        'username': username,
        'password': hashed_password
    })

    result = response.json()
    print(result)
    if result.get('success'):
        # 獲取用戶ID
        user_id_response = requests.get(f'{SERVER_API_BASE}/get_user_id/{username}')
        if user_id_response.status_code == 200:
            user_id = user_id_response.json().get('user_id')
            # 將用戶信息存儲到會話中
            session['user_id'] = user_id
            session['username'] = username
            print(f"Session set: user_id={user_id}, username={username}")        
        return redirect(url_for('to_driver_page'))
    else:
        print('Login failed.')
        return redirect(url_for('to_login_page'))

@Client.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        # generate PKC key pairs
        private_key, public_key= generate_key_pair()

        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        # store private key locally
        client_dir = os.path.dirname(__file__)
        user_key_dir = os.path.join(client_dir, "PKC_KEY", f"{username}_keys",)
        SK_file_name = f"{username}_private_key.pem"
        PK_file_name = f"{username}_public_key.pem"
        os.makedirs(user_key_dir, exist_ok=True)
        file_path = os.path.join(user_key_dir, SK_file_name)
        with open(file_path, "wb") as f:
            f.write(private_key)
        file_path = os.path.join(user_key_dir, PK_file_name)
        with open(file_path, "wb") as f:
            f.write(public_key)

        hashed_password,salt = hash_password(password)

        response = requests.post(f'{SERVER_API_BASE}/register', json={
            'email': email,
            'username': username,
            'password': hashed_password,
            'salt': salt,
            'public_key': public_key.decode() # Convert bytes to UTF-8 string
        })

        if response.json().get('success'):
            print('Registration successful. Now going to login page ...')
            return redirect(url_for('to_login_page'))
        else:
            print('Registration failed. The username you provided have already exist')
            return redirect(url_for('to_login_page'))

# CMS 填充實現
def cms_pad(data, block_size):
    # 計算需要添加的填充字節數
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size  # 如果恰好是塊大小的整數倍，添加一整個塊
    
    # 每個填充字節的值等於填充字節的數量
    padding = bytes([padding_length] * padding_length)
    
    # 將填充添加到數據末尾
    padded_data = data + padding
    
    return padded_data

# CMS 填充移除
def cms_unpad(padded_data):
    # 最後一個字節的值表示填充的字節數
    padding_length = padded_data[-1]
    
    # 驗證填充（可選，但建議）
    for i in range(1, padding_length + 1):
        if padded_data[-i] != padding_length:
            raise ValueError("invaild")
    
    # 移除填充
    data = padded_data[:-padding_length]
    
    return data

def cms_unpad(padded_data):
    padding_length = padded_data[-1]
    for i in range(1, padding_length + 1):
        if padded_data[-i] != padding_length:
            raise ValueError("Invalid padding")
    return padded_data[:-padding_length]

# encryption
def enc_file(file_data):

    key = Client.secret_key

    #generate IV
    iv = os.urandom(16) # AES block size

    #padding
    block_size = 16
    padded_data = cms_pad(file_data, block_size)

    # AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encrpytor = cipher.encryptor()
    encrypted_data = encrpytor.update(padded_data) + encrpytor.finalize()

    # Store the important information in json format in server for decryption
    metadata ={
        'iv': base64.b64encode(iv).decode('utf-8'),
        'mode': 'CBC',
        'algorithm': 'AES',
        'padding': 'CMS'
    }

    return encrypted_data, json.dumps(metadata)

# Decrypt file
def decrypt_file(encrypted_data, metadata, username, encrypted_AES_Key=None):

    # only shared user should use encrypted_AES_Key
    if encrypted_AES_Key!=None:
        # get local private key by username
        SK = retrieve_private_key(username)

        # Load the private key and decrypt the AES key
        try:
            # Load the PEM-encoded private key into an RSA private key object
            private_key = serialization.load_pem_private_key(
                SK,
                password=None,  # Assuming the private key is not password-protected
                backend=default_backend()
            )

            # Decrypt the encrypted_AES_Key using RSA-OAEP
            key = private_key.decrypt(
                encrypted_AES_Key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Verify the AES key length
            if len(key) != 32:
                raise ValueError("Decrypted AES key has incorrect length")

        except (ValueError, TypeError, Exception) as e:
            raise ValueError(f"Failed to decrypt AES key: {str(e)}")
    else:
        key=Client.secret_key

    # Take iv from metatdata
    metadata_dict = json.loads(metadata)
    iv = base64.b64decode(metadata_dict['iv'])

    # Implement AES-CBC decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # remove the CMS padding
    data = cms_unpad(padded_data)

    return data

@Client.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    data = request.get_json()
    file_data = bytes(data['file_data'])
    
    print(f"接收到加密請求：文件大小 {len(file_data)} 字節")
    
    # 使用現有的加密函數
    encrypted_data, metadata = enc_file(file_data)
    
    print(f"加密完成：加密後大小 {len(encrypted_data)} 字節")
    print(f"元數據：{metadata}")
    
    return jsonify({
        'encrypted_data': list(encrypted_data),
        'metadata': metadata
    })

@Client.route('/download/<file_id>')
def download_endpoint(file_id):

    user_id = session.get('user_id')

    key_response = requests.get(f"{SERVER_API_BASE}/get_encrypted_key/{file_id}", params={'user_id': user_id})
    if key_response.status_code == 200:
        key_data = key_response.json()
        if key_data.get('success'):
            encrypted_AES_Key_bytes = base64.b64decode(key_data['encrypted_key'])
        else:
            print("Error:", key_data.get('error'))
    else:
        print("Request failed with status:", key_response.status_code)

    if not user_id:
        return "Not logged in", 401
    
    # 從伺服器獲取加密文件
    response = requests.get(f'{SERVER_API_BASE}/download_file/{file_id}/{user_id}')
    
    if response.status_code != 200:
        return "Failed to download file", 400
    
    data = response.json()
    
    if not data.get('success'):
        return f"Download failed: {data.get('error', 'Unknown error')}"
    
    # 解碼數據
    encrypted_data = base64.b64decode(data.get('data'))
    metadata = data.get('metadata')
    filename = data.get('filename', f'file_{file_id}')
    username = data.get('username')
    owner = data.get('owner')
    
    try:
        # 解密數據
        if username != owner:
            decrypted_data = decrypt_file(encrypted_data, metadata,username,encrypted_AES_Key_bytes)
        else:
            decrypted_data = decrypt_file(encrypted_data, metadata,owner)

        # 返回解密後的文件
        return send_file(
            io.BytesIO(decrypted_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return f"Decryption failed: {str(e)}"


@Client.route('/fetch_files')
def fetch_files():
    user_id = session.get('user_id')
    print(f"Fetching files for user_id: {user_id}")
    if not user_id:
        return jsonify(error="Not logged in")
        
    response = requests.get(f'{SERVER_API_BASE}/list_files/{user_id}')
    return response.text, response.status_code, {'Content-Type': 'application/json'}


@Client.route('/get_current_user')
def get_current_user():
    if 'user_id' not in session:
        return jsonify(error="Not logged in"), 401
    
    return jsonify(user_id=session.get('user_id'), username=session.get('username'))

@Client.route('/get_encrypted_AES_Key/<shared_username>')
def get_encrypted_AES_Key(shared_username):
    response = requests.get(f'{SERVER_API_BASE}/get_public_key/{shared_username}')

    if response.status_code == 200:
        data = response.json()
        public_key = data['public_key']
    else:
        print(f"request fail，status_code: {response.status_code}")

    try:
        public_key = serialization.load_pem_public_key(
            public_key.encode('utf-8')
        )
    except ValueError as e:
        print({e})

    # use public key to encrypt secret_key (AES key)
    try:
        encrypted_AES_Key = public_key.encrypt(
            Client.secret_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"encrypt fail: {e}")

    encrypted_AES_Key_base64 = base64.b64encode(encrypted_AES_Key).decode('utf-8')

    return jsonify(success=True, encrypted_aes_key=encrypted_AES_Key_base64)

if __name__ == '__main__':
    Client.run(port=8080)
