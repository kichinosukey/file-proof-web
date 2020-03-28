# file-proof-web
Web based application of [file-proof](https://github.com/beyond-blockchain/bbc1/tree/develop/examples/file_proof)

# System requirement

- Python3.6 or later

# Installation

```
$ git clone https://github.com/kichinosukey/file-proof-web

$ cd file-proof-web

$ python3 -m venv venv

$ source venv/bin/activate

$ pip install bbc1

$ git clone https://github.com/beyond-blockchain/bbc1-lib-std.git

$ cd bbc1-lib-std/

$ python setup.py sdist

$ pip install dist/bbc1-lib-std-0.19.tar.gz # in 28 March 2020
```

# How to use

This application needs two consoles.

One is needed to start core node
```
$ bbc_core.py --no_nodekey 
```

And other is for start flask server
```
$ python index.py
```

Open your browser and access [application page](http://127.0.0.1:5000/fileproof).

Application menu  
- sign up
- sign in: initial keypair is created in this process
- setup: connect to domain
- store: store file
- get file
- update file
- verify file
- list: list transaction history

Replacement of keypair is processed after insertion of transaction automatically.