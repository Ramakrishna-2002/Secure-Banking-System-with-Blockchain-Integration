from flask import Flask
from flask_pymongo import PyMongo
from flask_cors import CORS
from web3 import Web3

mongo = PyMongo()
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))  # Connect to local Ethereum node

def create_app():
    app = Flask(__name__)
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/blockchain_db'
    app.config['SECRET_KEY'] = 'supersecretkey'  # Change this to a more secure key
    CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
    mongo.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    return app