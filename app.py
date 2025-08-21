from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import io
from flask import send_from_directory



app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return send_from_directory('frontend', 'index.html')
# --- QRNG ---
def generate_qrng(KEY_BITS=128, IV_BITS=128):
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)
    sim = Aer.get_backend('qasm_simulator')
    shots_needed = KEY_BITS + IV_BITS
    result = sim.run(transpile(qc, sim), shots=shots_needed, memory=True).result()
    bits = ''.join(result.get_memory())
    key_bits = bits[:KEY_BITS]
    iv_bits  = bits[KEY_BITS:KEY_BITS+IV_BITS]
    key_bytes = int(key_bits, 2).to_bytes(KEY_BITS // 8, 'big')
    iv_bytes  = int(iv_bits, 2).to_bytes(IV_BITS // 8, 'big')
    return key_bytes, iv_bytes

# --- AES Helpers ---
def aes_encrypt(data_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return base64.b64encode(encrypted).decode()

def aes_decrypt(enc_b64, key, iv):
    enc_bytes = base64.b64decode(enc_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc_bytes), AES.block_size)
    return decrypted

# --- Routes ---
@app.route('/generate_qrng', methods=['GET'])
def get_qrng():
    key, iv = generate_qrng()
    return jsonify({'key': key.hex(), 'iv': iv.hex()})

@app.route('/encrypt_text', methods=['POST'])
def encrypt_text():
    data = request.json
    text = data['text']
    key = bytes.fromhex(data['key'])
    iv = bytes.fromhex(data['iv'])

    # Handle if text is a list (image AES key)
    if isinstance(text, list):
        data_bytes = bytes(text)
    else:
        data_bytes = text.encode()

    encrypted = aes_encrypt(data_bytes, key, iv)
    return jsonify({'encrypted': encrypted})

@app.route('/decrypt_text', methods=['POST'])
def decrypt_text():
    data = request.json
    enc = data['encrypted']
    key = bytes.fromhex(data['key'])
    iv = bytes.fromhex(data['iv'])

    decrypted_bytes = aes_decrypt(enc, key, iv)
    # Return string if originally text, else list of integers
    try:
        return jsonify({'decrypted': decrypted_bytes.decode()})
    except:
        return jsonify({'decrypted': list(decrypted_bytes)})

@app.route('/encrypt_image', methods=['POST'])
def encrypt_image():
    key = bytes.fromhex(request.form['key'])
    iv = bytes.fromhex(request.form['iv'])
    file_bytes = request.files['image'].read()
    encrypted_b64 = aes_encrypt(file_bytes, key, iv)
    return jsonify({'encrypted': encrypted_b64})

@app.route('/decrypt_image', methods=['POST'])
def decrypt_image():
    key = bytes.fromhex(request.form['key'])
    iv = bytes.fromhex(request.form['iv'])
    encrypted_b64 = request.form['encrypted']
    decrypted_bytes = aes_decrypt(encrypted_b64, key, iv)
    return send_file(io.BytesIO(decrypted_bytes), mimetype='image/png', as_attachment=True, download_name='decrypted.png')


if __name__ == "__main__":
    app.run(debug=True)
