import os
import binascii
import json
from datetime import datetime

import requests
from flask import (
    Blueprint, jsonify, redirect, request, 
    render_template, send_file, session)
from werkzeug.utils import secure_filename

from bbc1.core import bbclib 
from bbc1.core.bbc_config import DEFAULT_CORE_PORT


MAPPING_FILE = ".bbc_id_mappings"
PUBLIC_KEY = ".public_key"
PRIVATE_KEY = ".private_key"
PREFIX_API = 'http://127.0.0.1:5000' #FIXME to be flexible
ALLOWED_EXTENSIONS = {'txt'}


fileproof = Blueprint('fileproof', __name__, static_folder='./static', template_folder='./templates')

domain_id = bbclib.get_new_id("file_proof_web", include_timestamp=False)
domain_id_str = bbclib.convert_id_to_string(domain_id)
asset_group_id = bbclib.get_new_id("file_proof_asset_group", include_timestamp=False)
asset_group_id_str = bbclib.convert_id_to_string(asset_group_id)
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

@fileproof.route('/get', methods=['GET'])
def set_get_filename():
    if session.get('username') is None:
        return redirect('/fileproof/sign-in')
    return render_template('fileproof/set_file.html', action='/fileproof/get/file')

@fileproof.route('/get/file', methods=['GET'])
def get_file():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    if request.method == 'GET':

        filename = request.args.get('file')

        fileinfo = get_id_from_mappings(os.path.basename(filename), asset_group_id)
        if fileinfo is None:
            return render_template('fileproof/message.html', 
                    message="%s is not found." % filename)

        r = requests.get(PREFIX_API + '/api/file', 
                params={
                    'asset_id_str': bbclib.convert_id_to_string(fileinfo['asset_id']),
                    'domain_id_str': domain_id_str,
                    'user_id_str': session['user_id_str'],
                    'asset_group_id_str': asset_group_id_str,
                    })

        res = r.json()

        out_file_name, ext = os.path.splitext(filename)
        if os.path.exists(filename):
            current_datetime = datetime.now()
            time_str = current_datetime.strftime('_%Y%m%d%H%M%S')
            out_file_name += (time_str + ext)
        else:
            out_file_name += ext

        with open(out_file_name, "wb") as outfile:
            outfile.write(binascii.a2b_hex(res['file']))

        return render_template('fileproof/message.html', 
                    message="done get %s" % out_file_name)

@fileproof.route('/keypair', methods=['GET'])
def get_keypair():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    r = requests.get(PREFIX_API + '/api/keypair')
    res = r.json()

    if r.status_code != 200:
        return render_template('fileproof/message.html', message="ERROR: Failed to create keypair.")

    privkey_str = res['private_key_str']
    pubkey_str = res['public_key_str']

    session['private_key_str'] = privkey_str
    session['public_key_str'] = pubkey_str

    return render_template('fileproof/message.html', 
                message="Keypair was created successfully.")

@fileproof.route('/list', methods=['GET'])
def list_transaction():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    if request.method == 'GET':

        asset_id_str = request.args.get('asset_id_str')
        count = request.args.get('count')
        direction = request.args.get('direction')
        start_from = request.args.get('start_from')
        until = request.args.get('until')
        user_id_search_str = request.args.get('user_id_str')

        r = requests.get(PREFIX_API + '/api/transactions', 
                params={
                    'asset_id_str': asset_id_str,
                    'asset_group_id_str': asset_group_id_str,
                    'count': count,
                    'domain_id_str': domain_id_str, 
                    'direction': direction,
                    'start_from': start_from,
                    'until': until,
                    'user_id_search_str': user_id_search_str,
                    'user_id_str': session['user_id_str']
                })
        res = r.json()

        return render_template('fileproof/list.html', 
                    transactions=res['transactions'])

@fileproof.route('/sign-in', methods=['GET', 'POST'])
def signin():

    if request.method == 'GET':
        return render_template('fileproof/sign-in.html')

    elif request.method == 'POST':
        
        password = request.form.get('password')
        if password is None or len(password) <= 0:
            return render_template('fileproof/message.html', message="ERROR: Password is missing.")
        password_digest = bbclib.get_new_id(password, include_timestamp=False)
        password_digest_str = bbclib.convert_id_to_string(password_digest)

        username = request.form.get('username')
        if username is None or len(username) <= 0:
            return render_template('fileproof/message.html', message='ERROR: User name is missing.')

        r = requests.get(PREFIX_API + '/api/user',
                params={
                    'password': password_digest_str,
                    'username': username
                })
        res = r.json()
        
        if r.status_code != 200:
            return render_template('fileproof/message.html', message=res['message'])

        session['username'] = username
        session['user_id_str'] = res['user_id_str']

        return render_template('fileproof/index.html')

@fileproof.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('fileproof/sign-up.html')

    elif request.method == 'POST':

        r = requests.get(PREFIX_API + '/api/domain')
        res = r.json()

        if r.status_code != 200:
            return render_template('fileproof/message.html', 
                    message="ERROR: Failed to connect core node to domain(%s)." % res['domain_id'])
        
        password = request.form.get('password')
        if password is None or len(password) <= 0:
            return render_template('fileproof/message.html', 
                    message="ERROR: Password is missing.")
        password_digest = bbclib.get_new_id(password, include_timestamp=False)
        password_digest_str = bbclib.convert_id_to_string(password_digest)
        
        username = request.form.get('username')
        if username is None or len(username) <= 0:
            return render_template('fileproof/message.html', message='ERROR: User name is missing.')

        r = requests.post(PREFIX_API + '/api/user', 
                json={
                    'password': password_digest_str,
                    'username': username
                })
        res = r.json()

        if r.status_code != 200:
            return render_template('fileproof/message.html', message=res['message'])

        return redirect('/fileproof/sign-in')

@fileproof.route('/store', methods=['GET', 'POST'])
def store_file():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    if request.method == 'GET':
        return render_template('fileproof/store_file.html', action='/fileproof/store')

    file = request.files.getlist('files')[0]
    if file and allowed_file(file.filename):
        data = file.read()
        data_non_bytes = binascii.b2a_hex(data).decode('utf-8')
        filename = secure_filename(file.filename)
        filepath = './' + filename #FIXME specific data directory is needed

    fileinfo = get_id_from_mappings(os.path.basename(filename), asset_group_id)
    if fileinfo is not None:
        return render_template('fileproof/message.html', 
                message="ERROR: File %s is already existed." % filename)

    user_info = "Owner is %s" % session['username']
    
    r = requests.post(PREFIX_API + '/api/file', 
            json={
                'asset_body': user_info,
                'asset_file': data_non_bytes,
                'asset_group_id_str': asset_group_id_str,
                'domain_id_str': domain_id_str, 
                'private_key_str': session['private_key_str'],
                'public_key_str': session['public_key_str'],
                'tx_id_str': None,
                'user_id_str': session['user_id_str']})
    res = r.json()

    if r.status_code != 200:
        return render_template('fileproof/message.html', message=res['message'])

    asset_ids = bbclib.convert_idstring_to_bytes(res['asset_ids_str'])
    transaction_id = bbclib.convert_idstring_to_bytes(res['transaction_id_str'])
    store_id_mappings(os.path.basename(filepath), asset_group_id, 
            transaction_id=transaction_id, asset_ids=asset_ids)

    message = "Store file was success. \n"
    message += "asset_id: %s \n" % res['asset_ids_str']
    message += "transaction_id: %s \n" % res['transaction_id_str']

    return render_template('fileproof/message.html', message=message)

@fileproof.route('/update', methods=['GET', 'POST'])
def update_file():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    if request.method == 'GET':
        return render_template('fileproof/store_file.html', action='/fileproof/update')

    elif request.method == 'POST':

        file = request.files.getlist('files')[0]
        if file and allowed_file(file.filename):
            data = file.read()
            data_non_bytes = binascii.b2a_hex(data).decode('utf-8')
            filename = secure_filename(file.filename)
            filepath = './' + filename #FIXME specific data directory is needed

        else:
            return render_template('fileproof/message.html', 
                    message='ERROR: file must be selected and allowed file type.')

        fileinfo = get_id_from_mappings(os.path.basename(filepath), asset_group_id_str)
        if fileinfo is None:
            return render_template('fileproof/message.html', message="ERROR: %s is already existed." % file.filename)

        user_info = "Owner is %s" % session['username']

        transaction_id = fileinfo['transaction_id']
        transaction_id_str = bbclib.convert_id_to_string(transaction_id)

        r = requests.post(PREFIX_API + '/api/file', 
                json={
                    'asset_body': user_info,
                    'asset_file': data_non_bytes,
                    'asset_group_id_str': asset_group_id_str,
                    'private_key_str': session['private_key_str'],
                    'public_key_str': session['public_key_str'],
                    'tx_id_str': transaction_id_str,
                    'user_id_str': session['user_id_str']})
        res = r.json()

        if r.status_code != 200:
            return render_template('fileproof/message.html', message=res['message'])

        asset_ids = bbclib.convert_idstring_to_bytes(res['asset_ids_str'])
        transaction_id = bbclib.convert_idstring_to_bytes(res['transaction_id_str'])
        store_id_mappings(os.path.basename(filepath), asset_group_id, 
                transaction_id=transaction_id, asset_ids=asset_ids)

        message = "File update was success.\n"
        message += "asset_ids: %s \n" % res['asset_ids_str']
        message += "transaction_id: %s \n" % res['transaction_id_str']

        return render_template('fileproof/message.html', message=message)

@fileproof.route('/verify', methods=['GET'])
def verify():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    if request.method == 'GET':
        return render_template('fileproof/set_file.html', action='/fileproof/verify/file')

@fileproof.route('/verify/file', methods=['GET'])
def verify_file():

    if session.get('username') is None:
        return redirect('/fileproof/sign-in')

    if request.method == 'GET':

        filename = request.args.get('file')
        fileinfo = get_id_from_mappings(os.path.basename(filename), asset_group_id)
        if fileinfo is None:
            return render_template('fileproof/message.html', 
                    message="%s is not found." % filename)

        asset_id = fileinfo['asset_id']
        asset_id_str = bbclib.convert_id_to_string(asset_id)

        r = requests.get(PREFIX_API + '/api/file/verification',
                    params={
                        'asset_id_str': asset_id_str,
                        'asset_group_id_str': asset_group_id_str,
                        'domain_id_str': domain_id_str,
                        'user_id_str': session['user_id_str']
                    })
        res = r.json()

        if r.status_code != 200:
            return render_template('fileproof/message.html', message=res['message'])

        return render_template('fileproof/message.html', 
                    message="%s is valid." % filename)