'use strict';
// Already trying to use a good module!
const base32 = require('thirty-two'),
      notp = require('notp'),
      QREncoder = require("qr").Encoder,
      util = require('util');

const totp = {},
      hotp = {};

/**
 * Generate Time One Time Password URI (otpauth://)
 *
 * @param key (OTP Key)
 * @param label (OTP Label)
 * @return OTP Auth URL
 *
 */

totp.create = function(key, label) {
  if (!key) return null;
  return util.format('otpauth://totp/%s?secret=%s', label, base32.encode(key).toString().replace(/=/g,''));
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
  if (!key) return null;
  return util.format('otpauth://hotp/%s?secret=%s', label, base32.encode(key).toString().replace(/=/g,''));
}

/**
 * Generate OTP QR Code
 *
 * @param uri (OTP Auth URL)
 * @param callback
 *
 */

totp.qrcode = function(uri, callback) {
  const encoder = new QREncoder;

  encoder.on("end", function(data) {
    callback(null, {
      uri: 'data:image/png;base64,' + data.toString("base64"), // URL Encoded by Base64 (If you enter into this web browser address bar, can be seen in the image)
      raw: data // RAW PNG!
    })
  });

  encoder.on('error', function(err) {
    callback(err)
  });

  encoder.encode(uri)
}

hotp.qrcode = function(uri, callback) {
  totp.qrcode(uri, callback)
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
  } else {
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
  } else {
    return false;
  }
}

module.exports.TOTP = totp;
module.exports.HOTP = hotp;
