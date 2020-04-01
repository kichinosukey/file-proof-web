import argparse
import binascii
import hashlib
import os
import json
import sys
from datetime import datetime

from flask import Blueprint, abort, g, jsonify, request

from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import ESUCCESS

from bbc1.lib.app_support_lib import Database
from bbc1.lib import id_lib


domain_id = bbclib.get_new_id("file_proof_web", include_timestamp=False)
domain_id_str = bbclib.convert_id_to_string(domain_id)

NAME_OF_DB = 'fileproof_db'

fileproof_user_table_definition = [
    ["user_id", "BLOB"],
    ["name", "TEXT"],
    ["password", "TEXT"],
    ["public_key", "BLOB"],
    ["private_key", "BLOB"]
]

IDX_USER_ID = 0
IDX_NAME = 1
IDX_PASSWORD = 2
IDX_PUBKEY = 3
IDX_PRIVKEY = 4

class User:

    def __init__(self, user_id, name, password, keypair):
        self.user_id = user_id
        self.name = name
        self.password = password
        self.keypair = keypair

    @staticmethod
    def from_row(row):
        return User(
            row[IDX_USER_ID],
            row[IDX_NAME],
            row[IDX_PASSWORD],
            bbclib.KeyPair(privkey=row[IDX_PRIVKEY], pubkey=row[IDX_PUBKEY])
        )


class Store:

    def __init__(self, domain_id):
        self.domain_id = domain_id
        self.db = Database()
        self.db.setup_db(self.domain_id, NAME_OF_DB)

    def close(self):
        self.db.close_db(self.domain_id, NAME_OF_DB)

    def get_user(self, user_id, table):
        rows = self.db.exec_sql(
            self.domain_id, 
            NAME_OF_DB,
            'select * from ' + table + ' where user_id=?',
            user_id
        )
        if len(rows) <= 0:
            return None
        return User.from_row(rows[0])

    def get_users(self, table):
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select * from ' + table
            )
        return [User.from_row(row) for row in rows]

    def read_user(self, name, table):
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select * from ' + table + ' where name=?',
            name
        )
        if len(rows) <= 0:
            return None
        return User.from_row(rows[0])

    def setup(self):
        self.db.create_table_in_db(self.domain_id, NAME_OF_DB, 
                'user_table', fileproof_user_table_definition, 
                primary_key=IDX_USER_ID, indices=[IDX_NAME])

    def update_keypair(self, user, table):
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'update ' + table + 'set public_key=?, private_key=? ' + \
            'where user_id=? and password=?',
            user.keypair.public_key,
            user.keypair.private_key,
            user.user_id,
            user.password
        )
    
    def update_password(self, password, user, table):
        self.db.exec_sql(
            self.domain_id, 
            NAME_OF_DB,
            'update ' + table + 'set password=? where user_id=? and password=?',
            password,
            user.user_id,
            user.password
        )

    def user_exists(self, name, table):
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select rowid from ' + table + ' where name=?',
            name
        )
        return len(rows) > 0

    def write_user(self, user, table):
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'insert into ' + table + ' values (?, ?, ?, ?, ?)',
            user.user_id,
            user.name,
            user.password,
            user.keypair.public_key,
            user.keypair.private_key
        )

def abort_by_missing_param(param):
    abort(400, {
        'code': 'Bad Request', 
        'message': '{0} is missing'.format(param)
    })

def get_asset_file(transaction, response_data):
    if KeyType.all_asset_files in response_data:
        asset_file_dict = response_data[KeyType.all_asset_files]
        asset_id = transaction.relations[0].asset.asset_id
        return asset_file_dict[asset_id]
    else:
        return None

def get_asset_body(transaction):
    return transaction.relations[0].asset.asset_body

def setup_bbc_client(domain_id, user_id):
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client

def store_proc(asset_body, asset_file, asset_group_id, domain_id, key_pair, user_id, txid=None):

    bbc_app_client = setup_bbc_client(domain_id, user_id)

    store_transaction = bbclib.make_transaction(relation_num=1, witness=True)
    bbclib.add_relation_asset(store_transaction, relation_idx=0, asset_group_id=asset_group_id,
                              user_id=user_id, asset_body=asset_body, asset_file=asset_file)
    store_transaction.witness.add_witness(user_id)

    if txid:
        bbc_app_client.search_transaction(txid)
        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            return None, None, "ERROR: %s" % response_data[KeyType.reason].decode()
        
        prev_tx, fmt_type = bbclib.deserialize(response_data[KeyType.transaction_data])

        keypair = bbclib.KeyPair(privkey=key_pair.private_key, pubkey=key_pair.public_key)
        if not keypair.verify(prev_tx.transaction_id, prev_tx.signatures[0].signature):
            return None, None, "ERROR: Signature or keypair is invalid."

        bbclib.add_relation_pointer(transaction=store_transaction, relation_idx=0,
                                    ref_transaction_id=prev_tx.transaction_id)

    sig = store_transaction.sign(private_key=key_pair.private_key,
                                 public_key=key_pair.public_key)
    store_transaction.get_sig_index(user_id)
    store_transaction.add_signature_object(user_id=user_id, signature=sig)
    store_transaction.digest()
    print(store_transaction)

    ret = bbc_app_client.insert_transaction(store_transaction)
    assert ret
    response_data = bbc_app_client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        return None, None, "ERROR: %s" % response_data[KeyType.reason].decode()

    transaction_id = response_data[KeyType.transaction_id]
    asset_ids = store_transaction.relations[0].asset.asset_id

    return asset_ids, transaction_id, None


api = Blueprint('api', __name__)


@api.before_request
def before_request():
    g.store = Store(domain_id)
    g.store.setup()
    g.idPubkeyMap = None


@api.route('/domain', methods=['GET'])
def connect_core_to_domain():

    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, 
            multiq=False, loglevel='all') 

    tmpclient.domain_setup(domain_id)
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()
    
    return jsonify(domain_id=domain_id_str), 200

@api.route('/file', methods=['GET', 'POST'])
def store_file():

    if request.method == 'GET':

        asset_id_str = request.args.get('asset_id_str')
        asset_id = bbclib.convert_idstring_to_bytes(asset_id_str)

        asset_group_id_str = request.args.get('asset_group_id_str')
        asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)
        
        user_id_str = request.args.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        bbc_app_client = setup_bbc_client(domain_id, user_id)

        ret = bbc_app_client.search_transaction_with_condition(
                asset_group_id=asset_group_id, asset_id=asset_id, user_id=user_id)
        assert ret

        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            return jsonify(message="ERROR: %s" % response_data[KeyType.reason].decode('utf-8')), 404
        
        transactions = [bbclib.deserialize(data) for data in response_data[KeyType.transactions]]
        get_transaction, fmt_type = transactions[0]

        if KeyType.all_asset_files in response_data:
            asset_file_dict = response_data[KeyType.all_asset_files]
            asset_id = get_transaction.relations[0].asset.asset_id
            data = asset_file_dict[asset_id]
        
        else:
            data = get_transaction.relations[0].asset.asset_body

        return jsonify({
            'file': binascii.b2a_hex(data).decode('utf-8'),
            'message': None,
            'status': 'success'
            })
            
    elif request.method == 'POST':
        asset_body = request.json.get('asset_body')

        asset_file = request.json.get('asset_file')
        asset_file_bytes = binascii.a2b_hex(asset_file)
        
        asset_group_id_str = request.json.get('asset_group_id_str')
        asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)
        
        private_key_str = request.json.get('private_key_str')
        private_key = bbclib.convert_idstring_to_bytes(private_key_str)
        
        public_key_str = request.json.get('public_key_str')
        public_key = bbclib.convert_idstring_to_bytes(public_key_str)
        
        keypair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)

        tx_id_str = request.json.get('tx_id_str')
        if tx_id_str is not None:
            tx_id = bbclib.convert_idstring_to_bytes(tx_id_str)
        else:
            tx_id = None
        
        user_id_str = request.json.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        asset_ids, transaction_id, message = \
            store_proc(asset_body, asset_file_bytes, asset_group_id, 
                domain_id, keypair, user_id, txid=tx_id)
        
        if message is not None:
            return jsonify(message=message), 404

        if asset_ids is None:
            return jsonify(message="ERROR: asset_id is not found"), 404

        if transaction_id is None:
            return jsonify(message="ERROR: transaction_id is not found"), 404

        return jsonify(asset_ids_str=bbclib.convert_id_to_string(asset_ids), 
                transaction_id_str=bbclib.convert_id_to_string(transaction_id)), 200

@api.route('/file/verification', methods=['GET'])
def verify_file():

    if request.method == 'GET':

        asset_id_str = request.args.get('asset_id_str')
        asset_id = bbclib.convert_idstring_to_bytes(asset_id_str)

        asset_group_id_str = request.args.get('asset_group_id_str')
        asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)

        user_id_str = request.args.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        bbc_app_client = setup_bbc_client(domain_id, user_id)

        ret = bbc_app_client.search_transaction_with_condition(
                asset_group_id=asset_group_id, asset_id=asset_id, user_id=user_id)
        assert ret

        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            return jsonify(message="ERROR: %s" % response_data[KeyType.reason].decode('utf-8')), 404
        
        transactions = [bbclib.deserialize(data) for data in response_data[KeyType.transactions]]

        transaction, fmt = transactions[0]

        digest = transaction.digest()
        if not transaction.signatures[0].verify(digest):
            return jsonify(message="ERROR: Transaction digest is invalid."), 404

        if get_asset_file(transaction, response_data) is not None:
            data = get_asset_file(transaction, response_data)
        else:
            data = get_asset_body(transaction)

        file_digest = hashlib.sha256(data).digest()
        if file_digest == transaction.relations[0].asset.asset_file_digest:
            return jsonify(), 200
        else:
            return jsonify(message="ERROR: Asset file digest is invalid."), 404

@api.route('/keypair', methods=['GET'])
def create_keypair():

    if request.method == 'GET':

        keypair = bbclib.KeyPair()
        keypair.generate()

        return jsonify(private_key_str=bbclib.convert_id_to_string(keypair.private_key), 
            public_key_str=bbclib.convert_id_to_string(keypair.public_key)), 200

@api.route('/new-keypair', methods=['POST'])
def replace_keypair():

    username = request.json.get('username')
    password_digest_str = request.json.get('password_digest_str')

    if username is None:
        return jsonify(message="user name is nothing."), 404
    user = g.store.read_user(username, 'user_table')

    if user is None:
        return jsonify(message='user {0} is not found'.format(username)), 404
    
    if user.password != password_digest_str:
        return jsonify(message='password is incorrect.'), 404

    keypair_old = user.keypair

    keypair = bbclib.KeyPair()
    keypair.generate()

    g.idPubkeyMap = id_lib.BBcIdPublickeyMap(domain_id)
    g.idPubkeyMap.update(user.user_id, 
            public_key_to_replace=[keypair.public_key], keypair=keypair_old)
    
    user.keypair = keypair
    g.store.update(user, 'user_table')

    return jsonify(pulic_key_str=bbclib.convert_id_to_string(keypair.public_key),
                private_key_str=bbclib.convert_id_to_string(keypair.private_key)), 200



@api.route('/transactions', methods=['GET'])
def get_transactions():

    if request.method == 'GET':

        asset_id_str = request.args.get('asset_id_str')
        if asset_id_str is not None:
            asset_id = bbclib.convert_idstring_to_bytes(asset_id_str)
        else:
            asset_id = None

        asset_group_id_str = request.args.get('asset_group_id_str')
        if asset_group_id_str is not None:
            asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)
        else:
            asset_group_id = None

        count = request.args.get('count')
        if count is None:
            count = 0

        direction = request.args.get('direction')
        if direction is None:
            direction = 0

        start_from = request.args.get('start_from')
        if start_from is None:
            start_from = None
        
        until = request.args.get('until')
        if until is None:
            until = None

        user_id_search_str = request.args.get('user_id_search_str')
        if user_id_search_str is not None:
            user_id_search = bbclib.convert_idstring_to_bytes(user_id_search_str)
        else:
            user_id_search = None
        
        user_id_str = request.args.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        bbc_app_client =setup_bbc_client(domain_id, user_id)

        ret = bbc_app_client.search_transaction_with_condition(
                asset_group_id=asset_group_id, asset_id=asset_id, user_id=user_id)
        assert ret

        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            return jsonify(message="ERROR: %s" % response_data[KeyType.reason].decode('utf-8')), 404
        
        transactions = [bbclib.deserialize(data) for data in response_data[KeyType.transactions]]

        dics = []
        for tx_tuple in transactions:
            tx, fmt_type = tx_tuple
            dics.append({
                'transaction_id': bbclib.convert_id_to_string(tx.transaction_id) ,
                'asset_group_id': bbclib.convert_id_to_string(tx.relations[0].asset_group_id),
                'asset_id': bbclib.convert_id_to_string(tx.relations[0].asset.asset_id),
                'user_id': bbclib.convert_id_to_string(tx.relations[0].asset.user_id),
                'timestamp': datetime.fromtimestamp(tx.timestamp / 1000)
            })
        
        return jsonify(transactions=dics), 200

@api.route('/user', methods=['GET'])
def list_users():

    users = g.store.get_users('uset_table')
    dics = [{'username': user.name, 'user_id': bbclib.convert_id_to_string(user.user_id)} for user in users]
    return jsonify(users=dics), 200

@api.route('/user', methods=['POST'])
def define_user():

    if request.method == 'POST':

        password = request.json.get('password_digest_str')
        if password is None:
            abort_by_missing_param('password_digest_str')
        
        username = request.json.get('username')
        if username is None:
            abort_by_missing_param('username')
        
        if g.store.user_exists(username, 'user_table'):
            return jsonify(message='user {0} is already defined.'.format(username)), 409

        idPubkeyMap = id_lib.BBcIdPublickeyMap(domain_id)
        user_id, keypairs = idPubkeyMap.create_user_id(num_pubkeys=1)

        g.store.write_user(User(user_id, username, password, keypairs[0]), 'user_table')

        return jsonify(public_key_str=bbclib.convert_id_to_string(keypairs[0].public_key),
                private_key_str=bbclib.convert_id_to_string(keypairs[0].private_key)), 200

@api.route('/user/keypair', methods=['GET'])
def get_user_keypair():
    
    username = request.args.get('username')
    password_digest_str = request.args.get('password_digest_str')

    user = g.store.read_user(username, 'user_table')
    if user is None:
        return jsonify(message='user {0} is not found'.format(username)), 404
    
    if user.password != password_digest_str:
        return jsonify(message='password is incorrect.'), 404

    return jsonify(username=username, 
            user_id_str=bbclib.convert_id_to_string(user.user_id),
            public_key_str=bbclib.convert_id_to_string(user.keypair.public_key),
            private_key_str=bbclib.convert_id_to_string(user.keypair.private_key)
            ), 200

