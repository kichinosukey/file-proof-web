import os
import binascii
import json

import requests
from flask import Blueprint, jsonify, request, render_template, send_file, session
from werkzeug.utils import secure_filename

from bbc1.core import bbclib 
from bbc1.core.bbc_config import DEFAULT_CORE_PORT


MAPPING_FILE = ".bbc_id_mappings"
PUBLIC_KEY = ".public_key"
PRIVATE_KEY = ".private_key"
PREFIX_API = 'http://127.0.0.1:5000' #FIXME to be flexible
ALLOWED_EXTENSIONS = {'txt'}


fileproof = Blueprint('fileproof', __name__, static_folder='./static', template_folder='./templates')


domain_id = bbclib.get_new_id("file_proof_test_domain", include_timestamp=False)
domain_id_str = bbclib.convert_id_to_string(domain_id)
asset_group_id = bbclib.get_new_id("file_proof_asset_group", include_timestamp=False)
asset_group_id_str = bbclib.convert_id_to_string(asset_group_id)
user_name = "user_default"
user_id = bbclib.get_new_id(user_name, include_timestamp=False)
user_id_str = bbclib.convert_id_to_string(user_id)
key_pair = None


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_id_from_mappings(name, asset_group_id):
    if not os.path.exists(MAPPING_FILE):
        return None
    asset_group_id_str = binascii.b2a_hex(asset_group_id).decode()
    with open(MAPPING_FILE, "r") as f:
        mapping = json.load(f)
    if mapping is None:
        return None
    if asset_group_id_str in mapping and name in mapping[asset_group_id_str]:
        result = dict()
        if 'transaction_id' in mapping[asset_group_id_str][name]:
            result['transaction_id'] = binascii.a2b_hex(mapping[asset_group_id_str][name]['transaction_id'])
        if 'asset_id' in mapping[asset_group_id_str][name]:
            if isinstance(mapping[asset_group_id_str][name]['asset_id'], list):
                entry = []
                for ast in mapping[asset_group_id_str][name]['asset_id']:
                    entry.append(binascii.a2b_hex(ast))
                result['asset_id'] = entry
            else:
                result['asset_id'] = binascii.a2b_hex(mapping[asset_group_id_str][name]['asset_id'])
        return result
    return None

def store_id_mappings(name, asset_group_id, transaction_id=None, asset_ids=None):
    if transaction_id is None and asset_ids is None:
        return
    mapping = dict()
    asset_group_id_str = binascii.b2a_hex(asset_group_id).decode()
    if os.path.exists(MAPPING_FILE):
        with open(MAPPING_FILE, "r") as f:
            mapping = json.load(f)
    mapping.setdefault(asset_group_id_str, dict()).setdefault(name, dict())
    if transaction_id is not None:
        mapping[asset_group_id_str][name]['transaction_id'] = binascii.b2a_hex(transaction_id).decode()
    if asset_ids is not None:
        if isinstance(asset_ids, list):
            entry = []
            for ast in asset_ids:
                entry.append(binascii.b2a_hex(ast))
            mapping[asset_group_id_str][name]['asset_id'] = entry
        else:
            mapping[asset_group_id_str][name]['asset_id'] = binascii.b2a_hex(asset_ids).decode()

        with open(MAPPING_FILE, "w") as f:
            json.dump(mapping, f, indent=4)

@fileproof.route('/')
def index():
    return render_template('fileproof/index.html')

@fileproof.route('/keypair', methods=['GET'])
def get_keypair():

    r = requests.get(PREFIX_API + '/api/keypair')
    res = r.json()

    privkey_str = res['private_key_str']
    pubkey_str = res['public_key_str']

    session['private_key_str'] = privkey_str
    session['public_key_str'] = pubkey_str

    return render_template('fileproof/keypair_success.html')

@fileproof.route('/setup', methods=['GET'])
def domain_setup():

    r = requests.post(PREFIX_API + '/api/domain', json={'domain_id_str': domain_id_str})
    res = r.json()

    return render_template('fileproof/setup_success.html', domain_id=res['domain_id_str'])

@fileproof.route('/store', methods=['GET', 'POST'])
def store_file():

    if request.method == 'GET':
        return render_template('fileproof/store_file.html')

    file = request.files.getlist('files')[0]
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = './' + filename #FIXME specific data directory is needed
        file.save(filepath)

    fileinfo = get_id_from_mappings(os.path.basename(filepath), asset_group_id)
    if fileinfo is not None:
        return render_template('fileproof/fileinfo_already_exists.html')
    
    with open(filepath, "rb") as fin:
        data = fin.read()
    data_non_bytes = binascii.b2a_hex(data).decode('utf-8')

    user_info = "Owner is %s" % user_name
    
    r = requests.post(PREFIX_API + '/api/file', 
            json={
                'asset_body': user_info,
                'asset_file': data_non_bytes,
                'asset_group_id_str': asset_group_id_str,
                'domain_id_str': domain_id_str, 
                'fileinfo': fileinfo,
                'private_key_str': session['private_key_str'],
                'public_key_str': session['public_key_str'],
                'user_id_str': user_id_str})

    res = r.json()
    asset_ids_str = res['asset_ids_str']
    asset_ids = binascii.a2b_hex(asset_ids_str)
    transaction_id_str = res['transaction_id_str']
    transaction_id = binascii.a2b_hex(transaction_id_str)

    store_id_mappings(os.path.basename(filepath), asset_group_id, 
            transaction_id=transaction_id, asset_ids=asset_ids)

    return jsonify({'asset_ids_str': asset_ids_str, 'transaction_id_str': transaction_id_str})