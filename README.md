
ssh-keychain is a RSA vault you can add, list and remove keys from.

[![Build Status](https://travis-ci.org/131/ssh-keychain.svg?branch=master)](https://travis-ci.org/131/ssh-keychain)
[![Coverage Status](https://coveralls.io/repos/github/131/ssh-keychain/badge.svg?branch=master)](https://coveralls.io/github/131/ssh-keychain?branch=master)
[![Version](https://img.shields.io/npm/v/ssh-keychain.svg)](https://www.npmjs.com/package/ssh-keychain)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](http://opensource.org/licenses/MIT)

This module is designed as a backend for [ssh-agent-js](https://github.com/131/ssh-agent-js), a nodejs SSH agent.


# API
```
const KeyChain = require('ssh-keychain');
var vault = new KeyChain(); //new empty vault

vault.add_key( fs.readFileSync('some/rsa/key.pem', 'utf-8), 'mykeycomment');

// vault.keys//list current keys in vault

vault.sign("mykeycomment" //or key fingerprint, new Buffer("SomePpayload to sign"));
```

## add_key(PEM encoded key or binary DER [, optionnal key name])
Add a key in the vault, with an optionnal key name.

## sign(fingerprint or key name, payload)
Sign the payload with the desired key

## remove_key(fingerprint or key name)
Remove the key from by its fingerprint (or key name) from the vault

## remove_keys()
Remove all keys from the vault



# Credits
* [131](https://github.com/131) author
* node-rsa