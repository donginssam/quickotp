# QuickOTP

[![NPM](https://img.shields.io/npm/v/quickotp.svg)](https://npmjs.org/package/quickotp)
[![NPM Downloads](https://img.shields.io/npm/dm/quickotp.svg)](https://npmjs.org/package/quickotp)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/donginssam/quickotp/blob/master/LICENSE)

A lightweight OTP library for Node.js with zero runtime dependencies.  
Generates and verifies TOTP/HOTP tokens compatible with Google Authenticator and similar apps.

## Requirements

Node.js >= 18

## Installation

```sh
npm install quickotp
# or
pnpm add quickotp
# or
yarn add quickotp
```

## Usage

### ESM

```js
import { TOTP, HOTP } from "quickotp";
```

### CommonJS

```js
const { TOTP, HOTP } = require("quickotp");
```

---

### TOTP (Time-based OTP)

```js
// Generate an otpauth:// URI to register with an authenticator app
const uri = TOTP.create("secretkey", "MyApp");
// → 'otpauth://totp/MyApp?secret=ONSWG4TFORQC...'

// Verify a token entered by the user
const valid = TOTP.verify("secretkey", "123456");
// → true or false
```

### HOTP (HMAC-based Counter OTP)

```js
const uri = HOTP.create("secretkey", "MyApp");
// → 'otpauth://hotp/MyApp?secret=ONSWG4TFORQC...'

const valid = HOTP.verify("secretkey", "123456", 0); // counter must be a non-negative safe integer
// → true or false
```

### QR Code generation (optional)

The `.qrcode()` method requires the `qrcode` package to be installed separately:

```sh
npm install qrcode
```

```js
const uri = TOTP.create("secretkey", "MyApp");
const dataUrl = await TOTP.qrcode(uri); // data:image/png;base64,...
```

---

## API

### `TOTP.create(key, label): string`

Returns an `otpauth://totp/` URI with the base32-encoded secret. Throws `TypeError` if `key` is empty.

### `TOTP.verify(key, token, window?): boolean`

Verifies a TOTP token against the current time. `window` controls how many 30-second steps in either direction are accepted (default: `1`).
Throws `TypeError` or `RangeError` if `window` is not a non-negative integer.

### `TOTP.qrcode(uri): Promise<string>`

Returns the URI encoded as a PNG data URL. Requires `qrcode` to be installed.

### `HOTP.create(key, label): string`

Returns an `otpauth://hotp/` URI with the base32-encoded secret. Throws `TypeError` if `key` is empty.

### `HOTP.verify(key, token, counter): boolean`

Verifies an HOTP token against the given counter value.
Throws `TypeError` or `RangeError` if `counter` is not a non-negative safe integer.

### `HOTP.qrcode(uri): Promise<string>`

Returns the URI encoded as a PNG data URL. Requires `qrcode` to be installed.

---

### Author: [Dongin Lee](https://github.com/donginssam)
