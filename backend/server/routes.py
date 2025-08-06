from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from .blockchain import Blockchain
from . import mongo, w3
import json
from bson import json_util
import jwt
import datetime
import logging

main = Blueprint('main', __name__)
blockchain = Blockchain()
secret_key = "supersecretkey"  # Change this to a more secure key

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@main.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    blockchain.new_transaction(
        sender="0",
        recipient=request.args.get('address'),
        amount=1,
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(proof, previous_hash)

    mongo.db.blocks.insert_one(block)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': blockchain.decode_data(block['transactions']),
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@main.route('/transactions/new', methods=['POST'])
def new_transaction():
    try:
        logger.debug(f"Received request: {request.data}")
        values = request.get_json()
        logger.debug(f"Parsed JSON: {values}")

        required = ['sender', 'recipient', 'amount', 'signature']
        if not all(k in values for k in required):
            missing = [k for k in required if k not in values]
            logger.warning(f"Missing required values: {missing}")
            return jsonify({'error': f'Missing required values: {missing}'}), 400
        
        if not blockchain.verify_transaction(values):
            logger.warning("Invalid transaction signature")
            return jsonify({'error': 'Invalid transaction signature. Transaction failed.'}), 400
        
        index = blockchain.new_transaction(
            values['sender'],
            values['recipient'],
            values['amount'],
            values.get('message')
        )
        
        response = {
            'message': f'Transaction successfully added to Block {index}. Transaction completed.',
            'block_index': index,
            'transaction': {
                'sender': values['sender'],
                'recipient': values['recipient'],
                'amount': values['amount'],
                'message': values.get('message')
            }
        }
        logger.info(f"Transaction added successfully: {response}")
        return jsonify(response), 201
    
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON payload: {e}")
        return jsonify({'error': 'Invalid JSON payload'}), 400
    except KeyError as e:
        logger.error(f"Missing key in payload: {e}")
        return jsonify({'error': f'Missing key in payload: {str(e)}'}), 400
    except ValueError as e:
        logger.error(f"Value error: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500




@main.route('/chain', methods=['GET'])
def full_chain():
    decoded_chain = blockchain.get_decoded_chain()
    response = {
        'chain': json.loads(json_util.dumps(decoded_chain)),
        'length': len(decoded_chain),
    }
    return jsonify(response), 200

@main.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    balance = w3.eth.get_balance(address)
    return jsonify({'balance': w3.from_wei(balance, 'ether')}), 200

@main.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    existing_user = mongo.db.users.find_one({"username": username})
    if existing_user:
        return jsonify({"message": "Username already exists"}), 400

    hashed_password = generate_password_hash(password)
    user_id = mongo.db.users.insert_one({
        "username": username,
        "password": hashed_password
    }).inserted_id

    return jsonify({"message": "User created successfully", "user_id": str(user_id)}), 201

@main.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = mongo.db.users.find_one({"username": username})
    if user and check_password_hash(user['password'], password):
        token = jwt.encode({
            'user_id': str(user['_id']),
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, secret_key, algorithm="HS256")
        return jsonify({"token": token, "user_id": str(user['_id'])}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@main.route('/transactions', methods=['GET'])
def get_transactions():
    all_transactions = []
    for block in blockchain.chain:
        transactions = blockchain.decode_data(block['transactions'])
        all_transactions.extend(transactions)
    return jsonify({'transactions': all_transactions}), 200