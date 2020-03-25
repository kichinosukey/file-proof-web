import argparse
import binascii
import hashlib
import os
import json
import sys
from datetime import datetime

from flask import Blueprint, jsonify, request

from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import ESUCCESS


def get_asset_file(transaction, response_data):
    if KeyType.all_asset_files in response_data:
        asset_file_dict = response_data[KeyType.all_asset_files]
        asset_id = transaction.relations[0].asset.asset_id
        return asset_file_dict[asset_id]
    else:
        return None

def get_asset_body(transaction):
    return transaction.relations[0].asset.asset_body

def get_tx_list(client, asset_group_id=None, asset_id=None, user_id=None, 
                    start_from=None, until=None, direction=0, count=0):

    ret = client.search_transaction_with_condition(
        asset_group_id=asset_group_id, asset_id=asset_id, user_id=user_id,
        start_from=start_from, until=until, direction=direction, count=count)
    assert ret

    response_data = client.callback.synchronize()
    if response_data[KeyType.status] < ESUCCESS:
        return None, None, "ERROR: %s" % response_data[KeyType.reason].decode('utf-8')
    
    transactions = [bbclib.deserialize(data) for data in response_data[KeyType.transactions]]

    return transactions, response_data, None

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
        print("ERROR: ", response_data[KeyType.reason].decode())
        sys.exit(0)

    transaction_id = response_data[KeyType.transaction_id]
    asset_ids = store_transaction.relations[0].asset.asset_id

    return asset_ids, transaction_id, None


api = Blueprint('api', __name__)


@api.route('/domain', methods=['POST'])
def setup():

    domain_id_str = request.json.get('domain_id_str')
    domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)

    tmpclient = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, 
            multiq=False, loglevel='all') 
    if os.path.exists('node_key.pem'):
        tmpclient.set_node_key('node_key.pem')
    tmpclient.domain_setup(domain_id)
    tmpclient.callback.synchronize()
    tmpclient.unregister_from_core()
    
    return jsonify({'domain_id_str': bbclib.convert_id_to_string(domain_id)})

@api.route('/file', methods=['GET', 'POST'])
def store_file():

    if request.method == 'GET':

        asset_id_str = request.args.get('asset_id_str')
        asset_id = bbclib.convert_idstring_to_bytes(asset_id_str)

        asset_group_id_str = request.args.get('asset_group_id_str')
        asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)
        
        domain_id_str = request.args.get('domain_id_str')
        domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
        
        user_id_str = request.args.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        bbc_app_client = setup_bbc_client(domain_id, user_id)
        transactions, response_data, msg = get_tx_list(bbc_app_client, 
                        asset_group_id=asset_group_id, asset_id=asset_id)
        if msg is not None:
            return jsonify({
                'file': None,
                'message': msg,
                'status': 'error'
                })

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
        
        domain_id_str = request.json.get('domain_id_str')
        domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
        
        private_key_str = request.json.get('private_key_str')
        private_key = bbclib.convert_idstring_to_bytes(private_key_str)
        
        public_key_str = request.json.get('public_key_str')
        public_key = bbclib.convert_idstring_to_bytes(public_key_str)
        
        keypair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)

        tx_id_str = request.json.get('tx_id_str')
        if tx_id_str is not None:
            tx_id = bbclib.convert_idstring_to_bytes(tx_id_str)
        else:
            tx_id = tx_id_str
        
        user_id_str = request.json.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        asset_ids, transaction_id, message = \
            store_proc(asset_body, asset_file_bytes, asset_group_id, 
                domain_id, keypair, user_id, txid=tx_id)

        if asset_ids is not None and transaction_id is not None:
            asset_ids_str = binascii.b2a_hex(asset_ids).decode('utf-8')
            transaction_id_str = binascii.b2a_hex(transaction_id).decode('utf-8')
            status = "success"
        else:
            asset_ids_str = None
            transaction_id_str = None
            status = "error"

        return jsonify({
            'asset_ids_str': asset_ids_str, 
            'transaction_id_str': transaction_id_str,
            'status': status,
            'message': message 
            })

@api.route('/file/verification', methods=['GET'])
def verify_file():

    if request.method == 'GET':

        asset_id_str = request.args.get('asset_id_str')
        asset_id = bbclib.convert_idstring_to_bytes(asset_id_str)

        asset_group_id_str = request.args.get('asset_group_id_str')
        asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)

        domain_id_str = request.args.get('domain_id_str')
        domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)

        user_id_str = request.args.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        bbc_app_client = setup_bbc_client(domain_id, user_id)

        transactions, response_data, msg = get_tx_list(\
            bbc_app_client, asset_group_id=asset_group_id, asset_id=asset_id)

        transaction, fmt = transactions[0]

        digest = transaction.digest()
        if not transaction.signatures[0].verify(digest):
            return jsonify({'status': 'invalid'})

        if get_asset_file(transaction, response_data) is not None:
            data = get_asset_file(transaction, response_data)
        else:
            data = get_asset_body(transaction)

        file_digest = hashlib.sha256(data).digest()
        if file_digest == transaction.relations[0].asset.asset_file_digest:
            return jsonify({'status': 'valid'})
        else:
            return jsonify({'status': 'invalid'})

@api.route('/keypair', methods=['GET'])
def create_keypair():

    if request.method == 'GET':

        keypair = bbclib.KeyPair()
        keypair.generate()

        return jsonify({
            'private_key_str': bbclib.convert_id_to_string(keypair.private_key), 
            'public_key_str': bbclib.convert_id_to_string(keypair.public_key)
            })

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
        
        domain_id_str = request.args.get('domain_id_str')
        domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)

        user_id_str = request.args.get('user_id_str')
        user_id = bbclib.convert_idstring_to_bytes(user_id_str)

        bbc_app_client =setup_bbc_client(domain_id, user_id)
        transactions, response_data, msg = get_tx_list(bbc_app_client, 
                asset_group_id=asset_group_id, asset_id=asset_id, 
                user_id=user_id_search, start_from=start_from, until=until, 
                direction=direction, count=count)
        
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
        
        return jsonify({'transactions': dics})