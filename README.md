# QuickOTP

[![Build Status](https://travis-ci.org/donginl/quickotp.svg?branch=master)](https://travis-ci.org/donginl/quickotp)
[![NPM](https://img.shields.io/npm/v/quickotp.svg)](https://npmjs.org/package/quickotp)
[![NPM Downloads](https://img.shields.io/npm/dm/quickotp.svg)](https://npmjs.org/package/quickotp)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)]()

Simplified, Quickly OTP Generate, Verify on Node.js!

This module dependency to the "qr" module.<br>
"qr" module, the operating system-specific additional installation you may need<br>
So, please check ["this link"](https://www.npmjs.com/package/qr).

## Installation
```
$ npm install quickotp
```

## Usage

```js
// Still I only support TOTP. soon I will support HOTP
var totp = require('quickotp').TOTP;

var uri = totp.create('key', 'label'); // Create TOTP! (May return the URL with "otpauth" schema)

var qrcode = totp.qrcode(uri, function(data) {
  console.log(data.uri); // data.uri is return a URL that has been encoded QRCode in Base64. (Content-Type: image/png)
});

var verify = totp.verify('key', 'token'); // Token (OTP Number) Valid check (If valid : return to 'true', invalid : return to false)
```

### Author: [DONG IN LEE](https://github.com/donginl)
