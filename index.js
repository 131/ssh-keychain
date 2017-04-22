"use strict";

const EventEmitter = require('events').EventEmitter;

const rsa    = require('node-rsa');
const pick   = require('mout/object/pick');
const forIn  = require('mout/object/forIn');

const pemme  = require('nyks/crypto/pemme');
const md5    = require('nyks/crypto/md5');

class KeyChain extends EventEmitter {

  constructor() {
    super();
    this._keys_list  = {};

    this.on("sign", function(){
      //console.log("In signing stuffs");
    });

  }

  add_key (body, comment) {

   if(Buffer.isBuffer(body))
      body = pemme(body, "RSA PRIVATE KEY");

    var key = new rsa(body, {signingScheme : 'pkcs1-sha1'});
    var details = key.exportKey('components');
 
    var writeb = function(data) {
      if(typeof data == "string") data = new Buffer(data);

      var body = data;
      if(!Buffer.isBuffer(body)) {
        body = new Buffer( 4);
        body.writeUInt32BE(data);
        body = body.slice(-Math.ceil(Math.log1p(data) /Math.log(256)) ); //trim leading zeros
      }
        

      var size = new Buffer(4); size.writeUInt32BE(body.length, 0);
      return Buffer.concat([size, body]);
    }
      //openssl public
    var publicKey = Buffer.concat([ writeb("ssh-rsa"), writeb(details.e), writeb(details.n) ]);
    var fingerprint = md5(publicKey);


    this.emit("add_key", {comment: comment} );

    this._keys_list[fingerprint] = {
        fingerprint,
        public : publicKey,
        private : key,
        comment : comment,
        algo    : 'rsa',
    };

  }

  _lookup(keyinfo) {
    if(keyinfo in this._keys_list)
      return this._keys_list[keyinfo];

    var k;
    forIn(this._keys_list, (key) => {
      if(key.comment == keyinfo)
        k = key;
    });
    return k;
  }

  sign (keyInfo, message) {

    //console.log("Request for signing of key", keyInfo);
    var key = this._lookup(keyInfo);
    if(!key)
      throw "Invalid key";

    var sign = key.private.sign(message);

    this.emit("sign", {fingerprint:key.fingerprint, comment:key.comment});
    return sign;
  }

  remove_key(fingerprint) {
    delete this._keys_list[fingerprint];
  }

  remove_keys() {
    this._keys_list = {};
  }

  get keys() {
    var keys = [];
    forIn(this._keys_list, (key, key_id) => {
      keys.push(pick(key, 'public', 'fingerprint', 'comment'));
    });

    this.emit("list_keys");
    return keys;
  }

}

module.exports = KeyChain;
