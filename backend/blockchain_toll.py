import hashlib
import json
from time import time
from flask import Flask, request, jsonify, render_template, make_response
from flask_cors import CORS
from cryptography.fernet import Fernet
import base64
import pdfkit

app = Flask(__name__)
CORS(app)

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

# Routes
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['car_number', 'owner', 'vehicle_type', 'toll_amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.new_transaction(
        values['car_number'],
        values['owner'],
        values['vehicle_type'],
        values['toll_amount']
    )
    return jsonify({'message': f'Transaction will be added to Block {index}'}), 201

@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    return jsonify({
        'message': 'New Block Forged',
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    chain_with_hashes = []
    for block in blockchain.chain:
        block_copy = block.copy()
        block_copy['present_hash'] = blockchain.hash(block)
        chain_with_hashes.append(block_copy)
    return jsonify({'chain': chain_with_hashes, 'length': len(chain_with_hashes)}), 200

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

@app.route('/generate_pdf')
def generate_pdf():
    try:
        # Collect all transactions from all blocks
        all_transactions = []
        for block in blockchain.chain:
            for tx in block['transactions']:
                decrypted = blockchain._decrypt_data(tx)
                all_transactions.append(decrypted)
        
        # Sort by timestamp
        all_transactions.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Generate PDF
        rendered = render_template('pdf_template.html', transactions=all_transactions)
        pdf = pdfkit.from_string(rendered, False)
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=toll_transactions.pdf'
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.template_filter('datetime')
def format_datetime(timestamp):
    from datetime import datetime
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

if __name__ == '__main__':
    app.run(port=5000)
