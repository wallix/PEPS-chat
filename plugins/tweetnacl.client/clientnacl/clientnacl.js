/**
 * @externType binary
 * @externType uint8array
 * @externType TweetNacl.keyPair
 */

/**
 * @register {int -> uint8array}
 */
function uint8array_of_int(n) {
  var bytes = [];
  while (n > 0) {
    bytes.push(n & 0xFF);
    n >>= 8;
  };
  return new Uint8Array(bytes);
}

/**
 * @register {uint8array -> int}
 */
function uint8array_length(array) {
  return array.length;
}

/**
 * @register {uint8array -> uint8array}
 */
function nacl_hash(msg) { return nacl.hash(msg); }

/**
 * @register {-> int}
 */
function nacl_hashLength() { return nacl.hash.hashLength; }


/**
 * @register {int -> uint8array}
 */
function nacl_randomBytes(length) { return nacl.randomBytes(length); }

/**
 * @register {uint8array, uint8array -> bool}
 */
function nacl_verify(array0, array1) { return nacl.verify(array0, array1); }

/**
 * @register {-> TweetNacl.keyPair}
 */
function nacl_sign_keyPair() { return nacl.sign.keyPair(); }

/**
 * @register {uint8array, uint8array -> uint8array}
 */
function nacl_sign(message, secretKey) { return nacl.sign(message, secretKey); }

/**
 * @register {uint8array, uint8array -> opa[option(uint8array)]}
 */
function nacl_sign_open(signature, publicKey) {
  var msg = nacl.sign.open(signature, publicKey);
  if (msg) return js_some(msg);
  else return js_none;
}

/**
 * @register {-> TweetNacl.keyPair}
 */
function nacl_box_keyPair() { return nacl.box.keyPair(); }

/**
 * @register {uint8array -> TweetNacl.keyPair}
 */
function nacl_box_keyPair_fromSecretKey(secretKey) { return nacl.box.keyPair.fromSecretKey(secretKey); }

/**
 * @register {uint8array, uint8array, uint8array, uint8array -> uint8array}
 */
function nacl_box(message, nonce, theirPublicKey, mySecretKey) { return nacl.box(message, nonce, theirPublicKey, mySecretKey); }

/**
 * @register {uint8array, uint8array, uint8array, uint8array -> opa[option(uint8array)]}
 */
function nacl_box_open(box, nonce, theirPublicKey, mySecretKey) {
  var msg = nacl.box.open(box, nonce, theirPublicKey, mySecretKey);
  if (msg) return js_some(msg);
  else return js_none;
}

/**
 * @register {uint8array, uint8array -> uint8array}
 */
function nacl_box_before(theirPublicKey, mySecretKey) { return nacl.box.before(theirPublicKey, mySecretKey); }

/**
 * @register {uint8array, uint8array, uint8array -> uint8array}
 */
function nacl_box_after(message, nonce, sharedKey) { return nacl.box.after(message, none, sharedKey); }

/**
 * @register {uint8array, uint8array, uint8array -> opa[option(uint8array)]}
 */
function nacl_box_open_after(box, nonce, sharedKey) {
  var msg = nacl.box.open.after(box, nonce, sharedKey);
  if (msg) return js_some(msg);
  else return js_none;
}

/**
 * @register {-> int}
 */
function nacl_box_publicKeyLength() { return nacl.box.publicKeyLength; }

/**
 * @register {-> int}
 */
function nacl_box_secretKeyLength() { return nacl.box.secretKeyLength; }

/**
 * @register {-> int}
 */
function nacl_box_sharedKeyLength() { return nacl.box.sharedKeyLength; }

/**
 * @register {-> int}
 */
function nacl_box_nonceLength() { return nacl.box.nonceLength; }

/**
 * @register {-> int}
 */
function nacl_box_overheadLength() { return nacl.box.overheadLength; }

/**
 * @register {uint8array, uint8array, uint8array -> uint8array}
 */
function nacl_secretbox(message, nonce, key) { return nacl.secretbox(message, nonce, key); }

/**
 * @register {uint8array, uint8array, uint8array -> opa[option(uint8array)]}
 */
function nacl_secretbox_open(message, nonce, key) {
  var msg = nacl.secretbox.open(message, nonce, key);
  if (msg) return js_some(msg);
  else return js_none;
}

/**
 * @register {-> int}
 */
function nacl_secretbox_keyLength() { return nacl.secretbox.keyLength }

/**
 * @register {-> int}
 */
function nacl_secretbox_nonceLength() { return nacl.secretbox.nonceLength }

/**
 * @register {-> int}
 */
function nacl_secretbox_overheadLength() { return nacl.secretbox.overheadLength }

/**
 * @register {string -> uint8array}
 */
function nacl_util_decodeUTF8(string) { return nacl.util.decodeUTF8(string); }

/**
 * @register {uint8array -> string}
 */
function nacl_util_encodeUTF8(array) { return nacl.util.encodeUTF8(array); }

/**
 * @register {string -> uint8array}
 */
function uint8array_decodeHex(hex) {
  var bytes = [];
  for(var i=0; i< hex.length-1; i+=2)
    bytes.push(parseInt(hex.substr(i, 2), 16));
  return new Uint8Array(bytes);
}

/**
 * @register {uint8array -> string}
 */
function uint8array_encodeHex(array) {
  var s = Array.prototype.map.call(array, function(n) {
    return (n >> 4).toString(16) + (n & 0xF).toString(16);
  }).join('');
  return s;
}

/**
 * @register {string -> uint8array}
 */
function nacl_util_decodeBase64(string) { return nacl.util.decodeBase64(string); }

/**
 * @register {uint8array -> string}
 */
function nacl_util_encodeBase64(array) { return nacl.util.encodeBase64(array); }


/**
 * @register {uint8array, uint8array -> uint8array}
 */
function hmac_sha512(key, data) {
  var blockSize = 128; // Bytes, specified in rfc4868.
  // If key is too long, apply sha512.
  if (key.byteLength > blockSize)
    key = nacl.hash(key);
  // If key is too short, add 0-padding to the right.
  if (key.byteLength < blockSize) {
    var tmpkey = new Uint8Array(new ArrayBuffer(blockSize));
    tmpkey.set(key, 0)
    key = tmpkey;
  }
  // Compute key pads.
  var okeypad = new Uint8Array(blockSize);
  uint8array_fill(okeypad, 0x5c);
  uint8array_xor(okeypad, key);
  var ikeypad = new Uint8Array(blockSize);
  uint8array_fill(ikeypad, 0x36);
  uint8array_xor(ikeypad, key);

  return nacl.hash(uint8array_concat(okeypad, nacl.hash(uint8array_concat(ikeypad, data))));
}

/**
 * @register {uint8array, uint8array, int, int -> uint8array}
 */
function pbkdf2(pass, salt, c, len) {
  var blockSize = 128; // Bytes, specified in rfc4868.
  var hashLength = 64;

  // Check derived key length. (4294967295 = 2^4294967295)
  if (len > 4294967295 * hashLength) throw "pbkdf2: derived key is too large";

  // Compute the HMAC key used for each iteration.
  // Algorithm is the same as HMAC.
  var key = pass;
  if (key.byteLength > blockSize)
    key = nacl.hash(key);
  if (key.byteLength < blockSize) {
    var tmpkey = new Uint8Array(new ArrayBuffer(blockSize));
    tmpkey.set(key, 0)
    key = tmpkey;
  }
  // Compute key pads.
  var okeypad = new Uint8Array(blockSize);
  uint8array_fill(okeypad, 0x5c);
  uint8array_xor(okeypad, key);
  var ikeypad = new Uint8Array(blockSize);
  uint8array_fill(ikeypad, 0x36);
  uint8array_xor(ikeypad, key);

  // Master key, initially empty.
  var masterKey = new Uint8Array(len);

  // Done with the preparations.
  // Apply hmac with the computed pads.
  function hmac(data) {
    return nacl.hash(uint8array_concat(okeypad, nacl.hash(uint8array_concat(ikeypad, data))));
  }

  // BIG endian encoding of integer i.
  function INT(i) {
    return new Uint8Array([(i>>24)&0xFF , (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF]);
  }

  // Check description of the algorithm
  // http://en.wikipedia.org/wiki/PBKDF2
  // also: rfc2898
  function F(salt, c, i) {
    var u = hmac(uint8array_concat(salt, INT(i)));
    var t = new Uint8Array(u);
    for (var n=1; n<c; n++) {
      u = hmac(u)
      uint8array_xor(t, u);
    }
    return t;
  }

  // Loop until the master key has been completed.
  var nLoop = len/hashLength; // Number of iterations.
  var clen = 0; // Accumulated length.
  var i = 1;
  for (; i<=nLoop; i++) {
    masterKey.set(F(salt, c, i), clen);
    clen += hashLength;
  }

  // Final iteration, possibly void.
  if (clen < len)
    masterKey.set(F(salt, c, i).subarray(0, len-clen), clen);

  // Return the master key.
  return masterKey;
}


/**
 * @register {uint8array, uint8array -> uint8array}
 */
function uint8array_concat(array0, array1) {
  var array = new Uint8Array(array0.byteLength + array1.byteLength)
  array.set(array0, 0);
  array.set(array1, array0.byteLength);
  return array;
}

/**
 * @register {uint8array, int -> uint8array}
 */
function uint8array_fill(array, value) {
  for (var i=0; i<array.byteLength; i++)
    array[i] = value;
}

/**
 * @register {uint8array, int -> uint8array}
 */
function uint8array_repeat(pattern, n) {
  if (n <= 0) return new Uint8Array([]);
  else {
    var patternSize = pattern.byteLength;
    var array = new Uint8Array(n * patternSize);
    for (var i=0; i<n; i++) {
      array.set(pattern, i*patternSize);
    }
    return array;
  }
}

/**
 * @register {uint8array, uint8array -> void}
 */
function uint8array_xor(array0, array1) {
  if (array0.byteLength == array1.byteLength) {
    for (var i=0; i<array0.byteLength; i++)
      array0[i] = array0[i] ^ array1[i];
  }
}

/**
 * @register {-> void}
 */
function HMACtest() {
  // HMAC-SHA512 tests extracted from rfc4868.
  var tests = [
    { key:  '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b' +
            '0b0b0b0b',
      data: '4869205468657265',
      res:  '87aa7cdea5ef619d4ff0b4241a1d6cb0' +
            '2379f4e2ce4ec2787ad0b30545e17cde' +
            'daa833b7d6b8a702038b274eaea3f4e4' +
            'be9d914eeb61f1702e696c203a126854' },
    { key:  '4a656665',
      data: '7768617420646f2079612077616e7420' +
            '666f72206e6f7468696e673f',
      res:  '164b7a7bfcf819e2e395fbe73b56e0a3' +
            '87bd64222e831fd610270cd7ea250554' +
            '9758bf75c05a994a6d034f65f8f0e6fd' +
            'caeab1a34d4a6b4b636e070a38bce737' },
    { key:  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaa',
      data: 'dddddddddddddddddddddddddddddddd' +
            'dddddddddddddddddddddddddddddddd' +
            'dddddddddddddddddddddddddddddddd' +
            'dddd',
      res:  'fa73b0089d56a284efb0f0756c890be9' +
            'b1b5dbdd8ee81a3655f83e33b2279d39' +
            'bf3e848279a722c806b485a47e67c807' +
            'b946a337bee8942674278859e13292fb' },
    { key:  '0102030405060708090a0b0c0d0e0f10' +
            '111213141516171819',
      data: 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
            'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
            'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd' +
            'cdcd',
      res:  'b0ba465637458c6990e5a8c5f61d4af7' +
            'e576d97ff94b872de76f8050361ee3db' +
            'a91ca5c11aa25eb4d679275cc5788063' +
            'a5f19741120c4f2de2adebeb10a298dd' },
    { key:  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaa',
      data: '54657374205573696e67204c61726765' +
            '72205468616e20426c6f636b2d53697a' +
            '65204b6579202d2048617368204b6579' +
            '204669727374',
      res:  '80b24263c7c1a3ebb71493c1dd7be8b4' +
            '9b46d1f41b4aeec1121b013783f8f352' +
            '6b56d037e05f2598bd0fd2215d6a1e52' +
            '95e64f73f63f0aec8b915a985d786598' },
    { key:  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
            'aaaaaa',
      data: '54686973206973206120746573742075' +
            '73696e672061206c6172676572207468' +
            '616e20626c6f636b2d73697a65206b65' +
            '7920616e642061206c61726765722074' +
            '68616e20626c6f636b2d73697a652064' +
            '6174612e20546865206b6579206e6565' +
            '647320746f2062652068617368656420' +
            '6265666f7265206265696e6720757365' +
            '642062792074686520484d414320616c' +
            '676f726974686d2e',
      res:  'e37b6a775dc87dbaa4dfa9f96e5e3ffd' +
            'debd71f8867289865df5a32d20cdc944' +
            'b6022cac3c4982b10d5eeb55c3e4de15' +
            '134676fb6de0446065c97440fa8c6a58' }
  ];

  for (var i=0; i<tests.length; i++) {
    var test = tests[i];
    var key = uint8array_decodeHex(test.key),
        data = uint8array_decodeHex(test.data),
        res = uint8array_decodeHex(test.res);
    var comp = hmac_sha512(key, data);
    if (nacl.verify(res, comp)) console.log('[HMAC]', 'test #' + i + ' successful');
    else if (res.byteLength != comp.byteLength) console.log('[HMAC]', 'test #' + i + ' failed (bad length)');
    else console.log('[HMAC]', 'test #' + i + ' failed (bad length)');
  }
}


/**
 * @register {-> void}
 */
function PBKDF2test() {
  // Test vectors imported from:
  // http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
  var tests = [
    { pass: 'password', salt: 'salt', c: 1, len: 64,
      res:  '867f70cf1ade02cff3752599a3a53dc4' +
            'af34c7a669815ae5d513554e1c8cf252' +
            'c02d470a285a0501bad999bfe943c08f' +
            '050235d7d68b1da55e63f73b60a57fce' },
    { pass: 'password', salt: 'salt', c: 2, len: 64,
      res:  'e1d9c16aa681708a45f5c7c4e215ceb6' +
            '6e011a2e9f0040713f18aefdb866d53c' +
            'f76cab2868a39b9f7840edce4fef5a82' +
            'be67335c77a6068e04112754f27ccf4e' },
    { pass: 'password', salt: 'salt', c: 4096, len: 64,
      res:  'd197b1b33db0143e018b12f3d1d1479e' +
            '6cdebdcc97c5c0f87f6902e072f457b5' +
            '143f30602641b3d55cd335988cb36b84' +
            '376060ecd532e039b742a239434af2d5' },
    { pass: 'passwordPASSWORDpassword',
      salt: 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
      c: 4096, len: 64,
      res:  '8c0511f4c6e597c6ac6315d8f0362e22' +
            '5f3c501495ba23b868c005174dc4ee71' +
            '115b59f9e60cd9532fa33e0f75aefe30' +
            '225c583a186cd82bd4daea9724a3d3b8' },
    { pass: 'passDATAb00AB7YxDTT', salt: 'saltKEYbcTcXHCBxtjD', c: 1, len: 64,
      res:  'CBE6088AD4359AF42E603C2A33760EF9' +
            'D4017A7B2AAD10AF46F992C660A0B461' +
            'ECB0DC2A79C2570941BEA6A08D15D688' +
            '7E79F32B132E1C134E9525EEDDD744FA' },
    { pass: 'passDATAb00AB7YxDTT', salt: 'saltKEYbcTcXHCBxtjD', c: 100000, len: 64,
      res:  'ACCDCD8798AE5CD85804739015EF2A11' +
            'E32591B7B7D16F76819B30B0D49D80E1' +
            'ABEA6C9822B80A1FDFE421E26F5603EC' +
            'A8A47A64C9A004FB5AF8229F762FF41F' },
    { pass: 'passDATAb00AB7YxDTTl', salt: 'saltKEYbcTcXHCBxtjD2', c: 1,  len: 64,
      res:  '8E5074A9513C1F1512C9B1DF1D8BFFA9' +
            'D8B4EF9105DFC16681222839560FB632' +
            '64BED6AABF761F180E912A66E0B53D65' +
            'EC88F6A1519E14804EBA6DC9DF137007' },
    { pass: 'passDATAb00AB7YxDTTl', salt: 'saltKEYbcTcXHCBxtjD2', c: 100000, len: 64,
      res:  '594256B0BD4D6C9F21A87F7BA5772A79' +
            '1A10E6110694F44365CD94670E57F1AE' +
            'CD797EF1D1001938719044C7F0180266' +
            '97845EB9AD97D97DE36AB8786AAB5096' },
    { pass: 'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5',
      salt: 'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe',
      c: 1, len: 63,
      res:  'E2CCC7827F1DD7C33041A98906A8FD7B' +
            'AE1920A55FCB8F831683F14F1C397935' +
            '1CB868717E5AB342D9A11ACF0B12D328' +
            '3931D609B06602DA33F8377D1F1F99' },
    { pass: 'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5',
      salt: 'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe',
      c: 100000, len: 63,
      res:  '07447401C85766E4AED583DE2E6BF5A6' +
            '75EABE4F3618281C95616F4FC1FDFE6E' +
            'CBC1C3982789D4FD941D6584EF534A78' +
            'BD37AE02555D9455E8F089FDB4DFB6' },
    { pass: 'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57',
      salt: 'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem',
      c: 1, len: 63,
      res:  'B029A551117FF36977F283F579DC7065' +
            'B352266EA243BDD3F920F24D4D141ED8' +
            'B6E02D96E2D3BDFB76F8D77BA8F4BB54' +
            '8996AD85BB6F11D01A015CE518F9A7' },
    { pass: 'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57',
      salt: 'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem',
      c: 100000, len: 63,
      res:  '31F5CC83ED0E948C05A15735D818703A' +
            'AA7BFF3F09F5169CAF5DBA6602A05A4D' +
            '5CFF5553D42E82E40516D6DC157B8DAE' +
            'AE61D3FEA456D964CB2F7F9A63BBBD' },
    { pass: 'passDATAb00AB7YxDTT', salt: 'saltKEYbcTcXHCBxtjD',
      c: 1, len: 65,
      res:  'CBE6088AD4359AF42E603C2A33760EF9' +
            'D4017A7B2AAD10AF46F992C660A0B461' +
            'ECB0DC2A79C2570941BEA6A08D15D688' +
            '7E79F32B132E1C134E9525EEDDD744FA' +
            '88' },
    { pass: 'passDATAb00AB7YxDTT', salt: 'saltKEYbcTcXHCBxtjD',
      c: 100000, len: 65,
      res:  'ACCDCD8798AE5CD85804739015EF2A11' +
            'E32591B7B7D16F76819B30B0D49D80E1' +
            'ABEA6C9822B80A1FDFE421E26F5603EC' +
            'A8A47A64C9A004FB5AF8229F762FF41F' +
            '7C' },
    { pass: 'passDATAb00AB7YxDTTl', salt: 'saltKEYbcTcXHCBxtjD2',
      c: 1, len: 65,
      res:  '8E5074A9513C1F1512C9B1DF1D8BFFA9' +
            'D8B4EF9105DFC16681222839560FB632' +
            '64BED6AABF761F180E912A66E0B53D65' +
            'EC88F6A1519E14804EBA6DC9DF137007' +
            '0B' },
    { pass: 'passDATAb00AB7YxDTTl', salt: 'saltKEYbcTcXHCBxtjD2',
      c: 100000, len: 65,
      res:  '594256B0BD4D6C9F21A87F7BA5772A79' +
            '1A10E6110694F44365CD94670E57F1AE' +
            'CD797EF1D1001938719044C7F0180266' +
            '97845EB9AD97D97DE36AB8786AAB5096' +
            'E7' }
  ];

  for (var i=0; i<tests.length; i++) {
    var test = tests[i];
    var pass = nacl.util.decodeUTF8(test.pass),
        salt = nacl.util.decodeUTF8(test.salt),
        res = uint8array_decodeHex(test.res);
    var comp = pbkdf2(pass, salt, test.c, test.len);
    if (nacl.verify(res, comp)) console.log('[PBKDF2]', 'test #' + i + ' successful');
    else if (res.byteLength != comp.byteLength) console.log('[PBKDF2]', 'test #' + i + ' failed (bad length)');
    else console.log('[PBKDF2]', 'test #' + i + ' failed (bad content)');
  }
}
