'use strict';
// Already trying to use a good module!
const base32 = require('thirty-two'),
      notp = require('notp'),
      QREncoder = require("qr").Encoder,
      util = require('util');

class totp {
    /**
     * Generate Time One Time Password URI (otpauth://)
     *
     * @param key (OTP Key)
     * @param label (OTP Label)
     * @return OTP Auth URL
     *
     */
    create(key, label) {
        if (!key) return null;
        return util.format('otpauth://totp/%s?secret=%s', label, base32.encode(key).toString().replace(/=/g,''));
    }

    /**
     * Generate OTP QR Code
     *
     * @param uri (OTP Auth URL)
     *
     */
    qrcode(uri) {
        return new Promise((resolve, reject) => {
            const encoder = new QREncoder;

            encoder.on("end", (data) => {
                resolve({
                    uri: 'data:image/png;base64,' + data.toString("base64"), // URL Encoded by Base64 (If you enter into this web browser address bar, can be seen in the image)
                    raw: data // RAW PNG!
                })
            });

            encoder.on('error', (err) => {
                reject(err)
            });

            encoder.encode(uri)
        });
    }

    /**
     * Verify Time OTP
     *
     * @param key (OTP Key)
     * @param token (OTP Token, as same as OTP Number)
     * @return Verify Result
     *
     */
    verify(key, token) {
        return !!notp.totp.verify(token, key);
    }
}

class hotp {
    /**
     * Generate HMAC (based Counter) One Time Password URI (otpauth://)
     *
     * @param key (OTP Key)
     * @param label (OTP Label)
     * @return OTP Auth URL
     *
     */
    create(key, label) {
        if (!key) return null;
        return util.format('otpauth://hotp/%s?secret=%s', label, base32.encode(key).toString().replace(/=/g,''));
    }

    qrcode(uri) {
        return new Promise((resolve, reject) => {
            const encoder = new QREncoder;

            encoder.on("end", (data) => {
                resolve({
                    uri: 'data:image/png;base64,' + data.toString("base64"), // URL Encoded by Base64 (If you enter into this web browser address bar, can be seen in the image)
                    raw: data // RAW PNG!
                })
            });

            encoder.on('error', (err) => {
                reject(err)
            });

            encoder.encode(uri)
        });
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

    verify(key, token, counter) {
        return !!notp.hotp.verify(token, key, {counter: counter});
    }
}

module.exports.TOTP = new totp();
module.exports.HOTP = new hotp();