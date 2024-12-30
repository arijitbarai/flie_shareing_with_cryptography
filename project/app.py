import os
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import sqlite3
import threading

app = Flask(__name__)

# Configurations
UPLOAD_FOLDER = 'uploads'
DATABASE = 'file_storage.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Generate RSA keys (for demonstration, use a persistent method in production)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()


# Function to serialize RSA keys (private and public)
def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# Initialize SQLite Database
def init_db():
    with sqlite3.connect(DATABASE, check_same_thread=False) as conn:  # Enable multi-threading
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            aes_key TEXT NOT NULL
        )''')
        conn.commit()


init_db()


# Utility: AES encryption
def encrypt_file(file_data):
    aes_key = os.urandom(32)  # Generate a random AES key
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    return aes_key, iv, encrypted_data


# Utility: RSA encryption for AES key
def encrypt_aes_key(aes_key):
    try:
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key
    except Exception as e:
        print(f"Error encrypting AES key: {e}")
        raise


# Utility: AES decryption
def decrypt_file(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


# Utility: RSA decryption for AES key
def decrypt_aes_key(encrypted_aes_key):
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Ensure AES key is of correct length (32 bytes for AES-256)
        if len(aes_key) != 32:
            raise ValueError(f"Incorrect AES key length: {len(aes_key)} bytes")

        return aes_key
    except Exception as e:
        print(f"Error during AES key decryption: {e}")
        raise


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    file_data = file.read()

    # Encrypt file
    aes_key, iv, encrypted_data = encrypt_file(file_data)

    # Encrypt AES key
    encrypted_aes_key = encrypt_aes_key(aes_key)

    # Save encrypted file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(file_path, 'wb') as f:
        f.write(iv + encrypted_data)

    # Save metadata in database
    def save_metadata():
        with sqlite3.connect(DATABASE, check_same_thread=False) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO files (filename, aes_key) VALUES (?, ?)',
                           (filename, base64.b64encode(encrypted_aes_key).decode()))
            conn.commit()

    threading.Thread(target=save_metadata).start()  # Run DB operation in a separate thread

    return jsonify({'message': 'File uploaded and encrypted successfully!', 'filename': filename})


@app.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404

    # Retrieve encrypted AES key from the database
    def retrieve_aes_key():
        with sqlite3.connect(DATABASE, check_same_thread=False) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT aes_key FROM files WHERE filename = ?', (filename,))
            row = cursor.fetchone()
            if not row:
                return None
            return base64.b64decode(row[0])

    encrypted_aes_key = retrieve_aes_key()
    if encrypted_aes_key is None:
        return jsonify({'error': 'Metadata not found'}), 404

    aes_key = decrypt_aes_key(encrypted_aes_key)

    # Read and decrypt file
    with open(file_path, 'rb') as f:
        file_content = f.read()

    iv = file_content[:16]  # Extract IV
    encrypted_data = file_content[16:]
    decrypted_data = decrypt_file(encrypted_data, aes_key, iv)

    # Serve decrypted file
    decrypted_path = f"decrypted_{filename}"
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    return send_file(decrypted_path, as_attachment=True)


@app.route('/')
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
