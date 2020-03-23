import argparse
import binascii
import datetime
import hashlib
import os
import json
import sys

from flask import Blueprint, jsonify, request

from bbc1.core import bbc_app
from bbc1.core.bbc_config import DEFAULT_CORE_PORT
from bbc1.core import bbclib
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_error import ESUCCESS


def setup_bbc_client(domain_id, user_id):
    bbc_app_client = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT, multiq=False, loglevel="all")
    bbc_app_client.set_user_id(user_id)
    bbc_app_client.set_domain_id(domain_id)
    bbc_app_client.set_callback(bbc_app.Callback())
    ret = bbc_app_client.register_to_core()
    assert ret
    return bbc_app_client

def store_proc(asset_body, asset_file, asset_group_id, domain_id, fileinfo, key_pair, user_id, txid=None):

    bbc_app_client = setup_bbc_client(domain_id, user_id)

    store_transaction = bbclib.make_transaction(relation_num=1, witness=True)
    bbclib.add_relation_asset(store_transaction, relation_idx=0, asset_group_id=asset_group_id,
                              user_id=user_id, asset_body=asset_body, asset_file=asset_file)
    store_transaction.witness.add_witness(user_id)

    if txid:
        bbc_app_client.search_transaction(txid)
        response_data = bbc_app_client.callback.synchronize()
        if response_data[KeyType.status] < ESUCCESS:
            print("ERROR: ", response_data[KeyType.reason].decode())
            sys.exit(0)
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

    return asset_ids, transaction_id


api = Blueprint('api', __name__)


@api.route('/keypair', methods=['GET'])
def create_keypair():

    if request.method == 'GET':

        keypair = bbclib.KeyPair()
        keypair.generate()

        return jsonify({
            'private_key_str': bbclib.convert_id_to_string(keypair.private_key), 
            'public_key_str': bbclib.convert_id_to_string(keypair.public_key)
            })

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

@api.route('/file', methods=['POST'])
def store_file():

    asset_body = request.json.get('asset_body')

    asset_file = request.json.get('asset_file')
    asset_file_bytes = binascii.a2b_hex(asset_file)
    
    asset_group_id_str = request.json.get('asset_group_id_str')
    asset_group_id = bbclib.convert_idstring_to_bytes(asset_group_id_str)
    
    domain_id_str = request.json.get('domain_id_str')
    domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
    
    fileinfo = request.json.get('fileinfo')
    
    private_key_str = request.json.get('private_key_str')
    private_key = bbclib.convert_idstring_to_bytes(private_key_str)
    
    public_key_str = request.json.get('public_key_str')
    public_key = bbclib.convert_idstring_to_bytes(public_key_str)
    
    keypair = bbclib.KeyPair(privkey=private_key, pubkey=public_key)
    
    user_id_str = request.json.get('user_id_str')
    user_id = bbclib.convert_idstring_to_bytes(user_id_str)
    
    asset_ids, transaction_id = store_proc(asset_body, asset_file_bytes, asset_group_id, domain_id, fileinfo, keypair, user_id)
    asset_ids_str = binascii.b2a_hex(asset_ids).decode('utf-8')
    transaction_id_str = binascii.b2a_hex(transaction_id).decode('utf-8')

    return jsonify({'asset_ids_str': asset_ids_str, 'transaction_id_str': transaction_id_str})