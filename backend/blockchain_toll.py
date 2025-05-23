import hashlib
import json
from time import time
from flask import Flask, request, jsonify, g, render_template, make_response
from flask_cors import CORS
from cryptography.fernet import Fernet
import base64
import sqlite3
import pdfkit   # pip install pdfkit
import os

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app)

# --- SQLite Setup ---
DATABASE = 'transactions.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Create the transactions table if it doesn't exist
with app.app_context():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            car_number TEXT,
            owner TEXT,
            vehicle_type TEXT,
            toll_amount REAL,
            timestamp REAL
        )
    ''')
    conn.commit()

# --- Blockchain Class ---
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, car_number, owner, vehicle_type, toll_amount):
        transaction_data = {
            'car_number': car_number,
            'owner': owner,
            'vehicle_type': vehicle_type,
            'toll_amount': toll_amount,
            'timestamp': time()
        }
        encrypted_data = self._encrypt_data(transaction_data)
        self.current_transactions.append(encrypted_data)
        return self.last_block['index'] + 1

    def _encrypt_data(self, data):
        data_str = json.dumps(data)
        encrypted = self.cipher.encrypt(data_str.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def _decrypt_data(self, encrypted_data_b64):
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data_b64.encode())
        decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
        return json.loads(decrypted_bytes.decode())

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True, default=str).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

blockchain = Blockchain()

# --- Flask Routes ---

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['car_number', 'owner', 'vehicle_type', 'toll_amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Save to SQLite
    try:
        conn = get_db()
        conn.execute('''
            INSERT INTO transactions 
            (car_number, owner, vehicle_type, toll_amount, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (values['car_number'], values['owner'],
              values['vehicle_type'], values['toll_amount'], time()))
        conn.commit()
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

    # Add to blockchain (encrypted)
    index = blockchain.new_transaction(
        values['car_number'],
        values['owner'],
        values['vehicle_type'],
        values['toll_amount']
    )
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    response = {
        'message': 'New Block Forged',
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    chain_with_hashes = []
    for block in blockchain.chain:
        block_copy = block.copy()
        block_copy['present_hash'] = blockchain.hash(block)
        chain_with_hashes.append(block_copy)
    response = {
        'chain': chain_with_hashes,
        'length': len(chain_with_hashes),
    }
    return jsonify(response), 200

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    data = request.get_json()
    if not data or 'data' not in data:
        return jsonify({"error": "No data provided"}), 400
    try:
        decrypted = blockchain._decrypt_data(data['data'])
        return jsonify(decrypted), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- PDF Generation ---

@app.template_filter('datetime')
def format_datetime(timestamp):
    from datetime import datetime
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/generate_pdf')
def generate_pdf():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM transactions ORDER BY timestamp DESC")
        transactions = [dict(row) for row in cur.fetchall()]
        # Render HTML template for PDF
        rendered = render_template('pdf_template.html', transactions=transactions)
        # Generate PDF from HTML
        pdf = pdfkit.from_string(rendered, False)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=toll_transactions.pdf'
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Make sure the templates directory exists for PDF rendering
    if not os.path.exists('templates'):
        os.makedirs('templates')
    print("Encryption key (keep this safe if you want to persist data!):", blockchain.encryption_key.decode())
    app.run(port=5000)
