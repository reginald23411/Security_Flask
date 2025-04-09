from flask import Flask, request, render_template, jsonify
import serverDBOperation
import base64
from flask_cors import CORS

Server = Flask(__name__)
CORS(Server)  # enable CORS

# checking if server is empty and initialize server for setting up from scratch
serverDBOperation.check_and_initialize_server()

# ------------respond page to client ---------------
@Server.route('/api/page/')
def login_page():
    return render_template("index.html",base_url=request.host_url)

@Server.route('/api/page/driver')
def driver_page():
    return render_template("success.html",base_url=request.host_url)
# ----------------------------------------------------

@Server.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    username = data['username']
    password = data['password']  # hashed from client
    salt = data['salt']
    public_key =data['public_key']

    # Store hashed password directly
    success = serverDBOperation.insert_record(
        serverDBOperation.register_query,
        (email, username, password,salt,public_key)
    )

    return jsonify(success=success)

@Server.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    hashed_password_input = data['password']  # hashed from client

    user_password = serverDBOperation.read_data(serverDBOperation.login_query, (username,))

    if user_password:
        stored_hashed = user_password[0][0]
        if stored_hashed == hashed_password_input:
            return jsonify(success=True)

    return jsonify(success=False)

# for client program login process use (encrypt data before sending to server)
@Server.route('/api/get_salt/<username>', methods=['GET'])
def get_salt(username):
    result = serverDBOperation.read_data(serverDBOperation.salt_query, (username,))
    if result:
        salt_hex = result[0][0]
        return jsonify(salt=salt_hex)
    else:
        return jsonify(error='User not found'), 404


# get user id
@Server.route('/api/get_user_id/<username>', methods = ['GET'])
def get_user_id(username):
    result = serverDBOperation.read_data(serverDBOperation.get_user_id_query, (username,))
    if result:
        return jsonify(user_id = result[0][0])
    return jsonify(error = "No user found"), 404


# upload file
@Server.route('/api/upload_file', methods = ['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify(success = False, error = "File missing!")
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success = False, error = "File missing!")
    
    # get data
    user_id = request.form.get('user_id')
    filename = request.form.get('filename')
    metadata = request.form.get('metadata')

    # verify file name avoid path attack
    if '..' in filename or '/' in filename or '\\' in filename:
        return jsonify (success = False, error = 'Invaild file!')
    
    # read cipher
    encrypted_data = file.read()

    # store encrypted data into database

    success = serverDBOperation.insert_record(
        serverDBOperation.upload_file_query,
        (user_id, filename, encrypted_data, metadata)
    )
    return jsonify (success = success)


# list user uploaded file
@Server.route('/api/list_files/<user_id>', methods = ['GET'])
def list_files(user_id):
    files = serverDBOperation.read_data(serverDBOperation.list_files_query, (user_id,))

    file_list = []
    for file in files:
        file_list.append({
            'id': file[0],
            'filename': file[1],
            'uploaded_at' : file[2]
        })
    
    # list the file shared
    shared_files = serverDBOperation.read_data(serverDBOperation.list_shared_files_query, (user_id,))

    for file in shared_files:
        file_list.append({
            'id' : file[0],
            'filename': file[1],
            'uploaded_at': file[2],
            'owner': file[3],
            'shared' : True
        })

    return jsonify(files=file_list)

# Download file
@Server.route('/api/download_file/<file_id>/<user_id>', methods = ['GET'])
def download_file(file_id, user_id):

    # check whether user have the right to access the file (upload by him/herself of shared)
    result = serverDBOperation.read_data(serverDBOperation.get_file_query, (file_id, user_id, user_id))
    username_result = serverDBOperation.read_data(serverDBOperation.get_username_query,user_id)
    owner_username_result= serverDBOperation.read_data(serverDBOperation.get_owner_query,(file_id,))

    if not result and username_result and owner_username_result:
        return jsonify(success=False, error = 'No access OR No file found')
    
    encrypted_data = result[0][0]
    metadata = result[0][1]
    filename = result[0][2]
    username = username_result[0][0]
    owner_username = owner_username_result[0][0]

    # encode data into transferable format
    encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

    return jsonify(success = True, data = encoded_data, metadata = metadata, filename = filename, username=username, owner=owner_username)

# Delete file
@Server.route('/api/delete_file/<file_id>/<user_id>', methods= ['DELETE'])
def delete_file(file_id, user_id):

    # only file owner can delete the file
    success = serverDBOperation.insert_record(serverDBOperation.delete_file_query, (file_id, user_id))
    return jsonify (success = success)

# Share file
@Server.route('/api/share_file', methods=['POST'])
def share_file():
    data = request.get_json()
    file_id = data['file_id']
    owner_id = data['owner_id']
    shared_with_username = data['shared_with_username']
    encrypted_aes_key = data['encrypted_aes_key']

    # get the user id for sharing
    shared_with_result = serverDBOperation.read_data(serverDBOperation.get_user_id_query, (shared_with_username,))

    if not shared_with_result:
        return jsonify (success=False, error = "No such username")
    
    shared_with_id = shared_with_result[0][0]

    # Confirm the file exitis and belong to the owner

    file_check = serverDBOperation.read_data(
        "SELECT id FROM files WHERE id = ? AND owner_id = ?", (file_id, owner_id)
    )

    if not file_check:
        return jsonify(success = False, error = "No access for sharing")
    
    # add log
    share_query = "INSERT INTO shared_files (file_id, shared_with_id, encrypted_AES_Key) VALUES (?, ?, ?)"
    success = serverDBOperation.insert_record(share_query, (file_id, shared_with_id, encrypted_aes_key))

    return jsonify(success=success)

# edit file name
@Server.route('/api/edit_file', methods=['PUT'])
def edit_file():
    data = request.get_json()
    file_id = data['file_id']
    user_id = data['user_id']
    new_filename = data['new_filename']

    # prevent path traversal attacks
    if '..' in new_filename or '/' in new_filename or '\\' in new_filename:
        return jsonify(success=False, error='Invalid filename')

    success = serverDBOperation.update_record(serverDBOperation.edit_file_name_query, (new_filename, file_id, user_id))

    return jsonify(success=success)

@Server.route('/api/get_public_key/<username>')
def get_public_key(username):
    result = serverDBOperation.read_data(serverDBOperation.get_PK_query,(username,))
    if not result:
        return jsonify(success=False, error="User not found")
    return jsonify(public_key=result[0][0])

@Server.route('/api/get_encrypted_key/<file_id>', methods=['GET'])
def get_encrypted_key(file_id):
    # Expect user_id to be passed as a query parameter
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify(success=False, error="Missing user_id"), 400

    # Look up encrypted AES key for this file and shared user
    query = """
        SELECT encrypted_AES_Key
        FROM shared_files
        WHERE file_id = ? AND shared_with_id = ?
    """
    result = serverDBOperation.read_data(query, (file_id, user_id))
    owner_result = serverDBOperation.read_data(serverDBOperation.get_owner_query,(file_id,))

    if result:
        encrypted_key = result[0][0]
        return jsonify(success=True, encrypted_key=encrypted_key)
    elif owner_result:
        return jsonify(success=True,owner_result=True)
    else:
        return jsonify(success=False, error="No shared AES key found or not authorized")

if __name__ == '__main__':
    Server.run()
