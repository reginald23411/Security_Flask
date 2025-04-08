import sqlite3
from sqlite3 import Error

DATABASE = 'server.db'
# prepare query
server_initialize_query='''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        salt VARCHAR(64) NOT NULL,
        public_key TEXT NOT NULL
    );
    '''
register_query = 'INSERT INTO users (email, username, password, salt, public_key) VALUES (?, ?, ?, ?, ?)'
login_query = "SELECT password FROM users WHERE username=?"
salt_query = "SELECT salt FROM users WHERE username=?"
edit_file_name_query="UPDATE files SET filename = ? WHERE id = ? AND owner_id = ?"
get_PK_query="SELECT public_key FROM users WHERE username=?"

# Establish database connection
def create_connection():
    conn = None
    try:
        # connect to server
        conn = sqlite3.connect(DATABASE)
        return conn
    except Error as e:
        print(e)
    return conn

# Execute a select query and fetch results
def read_data(query, params=None):
    conn = create_connection()
    results = []
    try:
        cur = conn.cursor()
        if params:
            cur.execute(query, params)
        else:
            cur.execute(query)
        results = cur.fetchall()
        cur.close()
    except Error as e:
        print(f"Error reading data: {e}")
    finally:
        if conn:
            conn.close()
    return results

# Insert record into database
def insert_record(query, params):
    conn = create_connection()
    success = False
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        success = True
        cur.close()
    except Error as e:
        print(f"Error inserting data: {e}")
    finally:
        if conn:
            conn.close()
    return success

def update_record(query, params):
    conn = create_connection()
    success = False
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        success = True
        cur.close()
    except Error as e:
        print(f"Error Updating data: {e}")
    finally:
        if conn:
            conn.close()
    return success


create_files_table_query = '''
CREATE TABLE IF NOT EXISTS  files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    encrypted_data BLOB,
    file_metadata TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users (id)
);
'''

create_shared_files_table_query ='''
CREATE TABLE IF NOT EXISTS shared_files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    shared_with_id INTEGER NOT NULL,
    encrypted_AES_Key TEXT DEFAULT NULL,
    shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES files (id),
    FOREIGN KEY (shared_with_id) REFERENCES users (id)
)
'''

upload_file_query = "INSERT INTO files (owner_id, filename, encrypted_data, file_metadata) VALUES (?, ?, ?, ?)"
get_file_query = "SELECT encrypted_data, file_metadata, filename FROM files WHERE id = ? AND (owner_id = ? OR id IN (SELECT file_id FROM shared_files WHERE shared_with_id = ?))"
list_files_query = "SELECT id, filename, uploaded_at FROM files WHERE owner_id = ?"
list_shared_files_query = "SELECT f.id, f.filename, f.uploaded_at, u.username AS owner FROM files f JOIN users u ON f.owner_id = u.id WHERE f.id IN (SELECT file_id FROM shared_files WHERE shared_with_id = ?)"
delete_file_query = "DELETE FROM files WHERE id = ? AND owner_id = ?"
get_user_id_query = "SELECT id FROM users WHERE username = ?"
get_username_query = "SELECT username FROM users WHERE id = ?"
get_owner_query = "SELECT u.username FROM files f JOIN users u ON f.owner_id = u.id WHERE f.id = ?"

def check_and_initialize_server():
    conn = create_connection()

    try:
        cur = conn.cursor()

        cur.execute(server_initialize_query)

        cur.execute(create_files_table_query)

        cur.execute(create_shared_files_table_query)

        conn.commit()

        print("Init complete")
        
        cur.close()
    
    except Error as e:
        print(f"Initiation Error: {e}")
    finally:
        if conn:
            conn.close()