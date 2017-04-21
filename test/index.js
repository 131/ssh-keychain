"use strict";

const fs = require('fs');
const path = require('path');

const expect = require('expect.js');
const KeyChain = require('../');
const rsa    = require('node-rsa');


describe("Testing keychain", function(){

  var vault;

  it("should init new keychain", function(){
    vault = new KeyChain();
    expect(vault.keys.length).to.be(0);
  });


  const mockKey   = fs.readFileSync(path.join(__dirname, 'mock/test.rsa'), "utf-8");
  const mockKeyFP = fs.readFileSync(path.join(__dirname, 'mock/test.rsa.fingerprint'), "utf-8")
                      .replace(new RegExp(':','g'), '').trim();

  const mockKeyDER   =   (new rsa(mockKey)).exportKey('pkcs1-der');

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
    var challenge =  new Buffer([132, 67, 170, 227, 161, 146, 157, 197, 141, 23, 37, 125, 123, 9, 130, 208, 107, 236, 127, 158, 193, 122, 129, 15, 13, 40, 249, 10, 148, 131, 38, 81, 200, 88, 131, 206, 78, 71, 216, 189, 223, 155, 216, 187, 187, 141, 131, 126, 53, 227, 139, 88, 171, 207, 24, 61, 34, 74, 234, 204, 137, 2, 191, 224, 155, 203, 172, 86, 9, 54, 124, 145, 153, 170, 140, 76, 126, 67, 29, 20, 78, 214, 41, 245, 129, 41, 77, 104, 205, 66, 223, 249, 88, 61, 90, 82, 82, 107, 249, 100, 218, 138, 96, 173, 175, 139, 13, 26, 194, 32, 48, 151, 163, 210, 197, 115, 24, 197, 130, 35, 225, 172, 49, 80, 18, 79, 101, 135, 120, 81, 252, 14, 154, 30, 27, 52, 48, 221, 117, 75, 142, 70, 55, 128, 22, 190, 214, 175, 44, 155, 147, 63, 167, 253, 141, 169, 224, 98, 164, 128, 240, 185, 150, 250, 200, 72, 9, 118, 87, 59, 210, 39, 170, 111, 121, 113, 118, 96, 88, 157, 239, 160, 238, 108, 26, 56, 168, 90, 159, 169, 138, 55, 141, 54, 82, 80, 80, 223, 85, 93, 5, 197, 190, 214, 101, 184, 244, 14, 191, 26, 167, 158, 112, 50, 56, 142, 53, 8, 161, 91, 81, 247, 138, 27, 91, 14, 127, 153, 83, 111, 63, 235, 243, 253, 132, 110, 187, 125, 0, 12, 41, 175, 250, 17, 241, 237, 112, 122, 75, 128, 233, 70, 161, 134, 190, 201]);

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