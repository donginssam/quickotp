'use strict';

// Already trying to use a good module!
var notp = require('notp');
var base32 = require('thirty-two');
var QREncoder = require("qr").Encoder;

var totp = {};
var hotp = {};

/**
 * Generate Time One Time Password URI (otpauth://)
 *
 * @param key (OTP Key)
 * @param label (OTP Label)
 * @return OTP Auth URL
 *
 */

totp.create = function(key, label) {
 return 'otpauth://totp/' + label +'?secret=' + base32.encode(key).toString().replace(/=/g,'');
}

/**
 * Generate HMAC (based Counter) One Time Password URI (otpauth://)
 *
 * @param key (OTP Key)
 * @param label (OTP Label)
 * @return OTP Auth URL
 *
 */

hotp.create = function(key, label) {
 return 'otpauth://hotp/' + label +'?secret=' + base32.encode(key).toString().replace(/=/g,'');
}

/**
 * Generate OTP QR Code
 *
 * @param uri (OTP Auth URL)
 * @param callback
 *
 */

totp.qrcode = function(uri, callback) {
  var encoder = new QREncoder;
  encoder.on("end", function(data) {
    callback({
      uri: 'data:image/png;base64,' + data.toString("base64"), // URL Encoded by Base64 (If you enter into this web browser address bar, can be seen in the image)
      raw: data // RAW PNG!
    });
  });
  encoder.encode(uri);
}

hotp.qrcode = function(uri, callback) {
  totp.qrcode(uri, callback);
}

/**
 * Verify Time OTP
 *
 * @param key (OTP Key)
 * @param token (OTP Token, as same as OTP Number)
 * @return Verify Result
 *
 */

totp.verify = function(key, token) {
  if (notp.totp.verify(token, key)) {
    return true;
  }
  else {
    return false;
  }
}

/**
 * Verify HMAC OTP
 *
 * @param key (OTP Key)
 * @param token (OTP Token, as same as OTP Number)
 * @param counter (OTP Counter)
 * @return Verify Result
 *
 */

hotp.verify = function(key, token, counter) {
  if (notp.hotp.verify(token, key, {counter: counter})) {
    return true;
  }
  else {
    return false;
  }
}

module.exports.TOTP = totp;
module.exports.HOTP = hotp;
