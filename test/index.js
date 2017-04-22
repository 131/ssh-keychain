"use strict";

const fs = require('fs');
const path = require('path');

const expect = require('expect.js');
const KeyChain = require('../');
const NodeRSA  = require('node-rsa');


describe("Testing keychain", function(){

  var vault;

  it("should init new keychain", function(){
    vault = new KeyChain();
    expect(vault.keys.length).to.be(0);
  });


  var mockKeyFP = '10a15d351701f11bf9dbfcd728917a5e';
  const mockKey   = fs.readFileSync(path.join(__dirname, 'mock', mockKeyFP), "utf-8");


  const pkey      = new NodeRSA(mockKey);
  const mockKeyDER   =   pkey.exportKey('pkcs1-der');


console.log(pkey.exportKey('components'));

  it("should add new key in keychain", function(){
    vault.add_key(mockKey);

    expect(vault.keys.length).to.be(1);
  });


  it("should add new key (binary format) in keychain", function(){
    vault.add_key(mockKeyDER);

    expect(vault.keys.length).to.be(1);
  });


  it("should remove key from keychain", function(){
    vault.remove_key(mockKeyFP);
    expect(vault.keys.length).to.be(0);

    vault.add_key(mockKey); //add it twice, nothing special
    vault.add_key(mockKey, "signing test key");
    expect(vault.keys.length).to.be(1);
  });




  it("should test signing", function(){
    var message=  "this is body";
    var challenge =  new Buffer([61, 237, 130, 149, 33, 45, 90, 24, 100, 96, 78, 34, 226, 101, 8, 9, 207, 95, 183, 98, 202, 115, 132, 56, 188, 203, 86, 167, 198, 226, 64, 25, 208, 11, 244, 31, 53, 197, 112, 160, 57, 27, 211, 151, 242, 54, 153, 145, 128, 110, 118, 29, 181, 32, 46, 50, 176, 47, 137, 83, 136, 34, 196, 9, 26, 214, 12, 168, 4, 115, 3, 89, 124, 21, 117, 96, 49, 234, 32, 237, 106, 27, 71, 76, 67, 140, 124, 245, 91, 202, 99, 233, 20, 204, 78, 216, 159, 60, 114, 166, 81, 80, 233, 28, 24, 24, 115, 46, 7, 102, 200, 11, 246, 73, 159, 116, 10, 38, 200, 192, 238, 23, 248, 205, 165, 82, 66, 5, 31, 121, 20, 31, 5, 129, 22, 163, 94, 92, 189, 235, 169, 222, 100, 32, 115, 198, 88, 95, 24, 34, 132, 9, 174, 67, 235, 47, 110, 227, 25, 254, 154, 234, 255, 162, 64, 40, 94, 120, 154, 165, 120, 143, 67, 10, 75, 120, 236, 73, 209, 225, 161, 180, 201, 169, 98, 130, 44, 248, 47, 151, 135, 81, 134, 197, 168, 68, 230, 193, 18, 39, 152, 206, 17, 55, 130, 208, 169, 161, 182, 30, 18, 15, 174, 31, 166, 229, 120, 52, 239, 33, 152, 176, 227, 3, 19, 223, 31, 145, 50, 154, 42, 155, 74, 148, 69, 65, 35, 27, 163, 173, 115, 45, 84, 245, 212, 210, 39, 26, 158, 40, 101, 108, 102, 84, 129, 32]);

    var sign = vault.sign("signing test key", message);
      expect(sign).to.eql(challenge);

      //check sign using fingerprint
    sign = vault.sign(mockKeyFP, message);
      expect(sign).to.eql(challenge);

      //signing with an invalid key throw an error
    try {
      sign = vault.sign("nope", message);
      expect().to.fail("Never here");
    } catch(err) {
      expect(err).to.eql("Invalid key");
    }
    
  });


  it("should remove all keys from keychain", function(){
    vault.remove_keys();
    expect(vault.keys.length).to.eql(0);
  });


});