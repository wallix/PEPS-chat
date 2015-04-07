package tweetnacl.client

type TweetNacl.keyPair = {
  uint8array secretKey,
  uint8array publicKey
}

/** Abstraction of Uint8Array. */
type uint8array = external

client module Uint8Array {

  function length(uint8array array) { %%ClientNacl.uint8array_length%%(array) }
  function repeat(uint8array pattern, int count) { %%ClientNacl.uint8array_repeat%%(pattern, count) }
  function fill(uint8array array, int value) { %%ClientNacl.uint8array_fill%%(array, value) }
  function concat(uint8array array0, uint8array array1) { %%ClientNacl.uint8array_concat%%(array0, array1) }

  function ofInt(int n) { %%ClientNacl.uint8array_of_int%%(n) }

  function decodeUTF8(string msg) { %%ClientNacl.nacl_util_decodeUTF8%%(msg) }
  function encodeUTF8(uint8array array) { %%ClientNacl.nacl_util_encodeUTF8%%(array) }
  function decodeHex(string msg) { %%ClientNacl.uint8array_decodeHex%%(msg) }
  function encodeHex(uint8array array) { %%ClientNacl.uint8array_encodeHex%%(array) }
  function decodeBase64(string msg) { %%ClientNacl.nacl_util_decodeBase64%%(msg) }
  function encodeBase64(uint8array array) { %%ClientNacl.nacl_util_encodeBase64%%(array) }

} // END UINT8ARRAY

client module TweetNacl {

  function hash(uint8array msg) { %%ClientNacl.nacl_hash%%(msg) }
  function randomBytes(int length) { %%ClientNacl.nacl_randomBytes%%(length) }
  function verify(uint8array array0, uint8array array1) { %%ClientNacl.nacl_verify%%(array0, array1) }

  /** Implementation of HMAC-SHA512 algorithm. */
  function hmac(uint8array key, uint8array data) { %%ClientNacl.hmac_sha512%%(key, data) }
  /** Implementation of the pbkdf2 algorithm (http://en.wikipedia.org/wiki/PBKDF2). */
  function pbkdf2(pass, salt, c, len) { %%ClientNacl.pbkdf2%%(pass, salt, c, len) }

  hashLength = %%ClientNacl.nacl_hashLength%%()
  hmacLength = %%ClientNacl.nacl_hashLength%%()

  module Sign {

    function keyPair() { %%ClientNacl.nacl_sign_keyPair%%() }
    function sign(uint8array msg, uint8array secretKey) { %%ClientNacl.nacl_sign%%(msg, secretKey) }
    function open(uint8array signature, uint8array publicKey) { %%ClientNacl.nacl_sign_open%%(signature, publicKey) }

  } // END SIGN

  module Box {

    function keyPair() { %%ClientNacl.nacl_box_keyPair%%() }
    function keyPairFromSecretKey(secretKey) { %%ClientNacl.nacl_box_keyPair_fromSecretKey%%(secretKey) }
    function box(message, nonce, theirPublicKey, mySecretKey) { %%ClientNacl.nacl_box%%(message, nonce, theirPublicKey, mySecretKey) }
    function open(box, nonce, theirPublicKey, mySecretKey) { %%ClientNacl.nacl_box_open%%(box, nonce, theirPublicKey, mySecretKey) }
    function before(theirPublicKey, mySecretKey) { %%ClientNacl.nacl_box_before%%(theirPublicKey, mySecretKey) }
    function after(message, nonce, sharedKey) { %%ClientNacl.nacl_box_after%%(message, nonce, sharedKey) }
    function openAfter(box, nonce, sharedKey) { %%ClientNacl.nacl_box_open_after%%(box, nonce, sharedKey) }

    publicKeyLength = %%ClientNacl.nacl_box_publicKeyLength%%()
    secretKeyLength = %%ClientNacl.nacl_box_secretKeyLength%%()
    sharedKeyLength = %%ClientNacl.nacl_box_sharedKeyLength%%()
    nonceLength = %%ClientNacl.nacl_box_nonceLength%%()
    overheadLength = %%ClientNacl.nacl_box_overheadLength%%()

  } // END BOX

  module SecretBox {

    function box(message, nonce, key) { %%ClientNacl.nacl_secretbox%%(message, nonce, key) }
    function open(message, nonce, key) { %%ClientNacl.nacl_secretbox_open%%(message, nonce, key) }

    keyLength = %%ClientNacl.nacl_secretbox_keyLength%%()
    nonceLength = %%ClientNacl.nacl_secretbox_nonceLength%%()
    overheadLength = %%ClientNacl.nacl_secretbox_overheadLength%%()

  } // END SECRETBOX

}
