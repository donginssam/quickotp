# QuickOTP

[![Build Status](https://travis-ci.org/donginl/quickotp.svg?branch=master)](https://travis-ci.org/donginl/quickotp)
[![NPM](https://img.shields.io/npm/v/quickotp.svg)](https://npmjs.org/package/quickotp)
[![NPM Downloads](https://img.shields.io/npm/dm/quickotp.svg)](https://npmjs.org/package/quickotp)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)]()
[![Donate](https://img.shields.io/gratipay/donginl.svg)]()

간결하고, 빠르게 소프트웨어 OTP 를 생성하고 인증하는 것을 Node.js 에서!
이 모듈에서 생성된 OTP는 Google Authenticator 와 비슷한 애플리케이션을 지원합니다.

## 지원하는 플랫폼
`quickotp`는 Node.js v0.10.x 이후 부터 최신버전 까지 지원합니다

## 공지사항
이 모듈은 `qr` 모듈을 참조합니다.<br>
`qr` 모듈은 시스템별로 추가 설치가 필요할 수 있습니다.<br>
따라서 [이 링크](https://www.npmjs.com/package/qr) 를 꼭 확인하시기 바랍니다.

## 설치
```
$ npm install quickotp
```

## 사용방법

```js
// TOTP 를 사용하려면...
var totp = require('quickotp').TOTP;
// HOTP 를 사용하려면...
var hotp = require('quickotp').HOTP;

var uri = totp.create('key', 'label'); // TOTP 형 소프트웨어 OTP 를 생성합니다! ("otpauth" 스키마를 지닌 URL 이 반환됩니다)
var uri = hotp.create('key', 'label'); // 또는 HOTP 형 소프트웨어 OTP 를 생성합니다! ("otpauth" 스키마를 지닌 URL 이 반환됩니다)

// OTPAuth URL 의 QRCode 를 생성한다. (두 가지의 방법이 있으나, 둘 다 동일한 방법이다.)
// 첫번째 방법 (TOTP 사용시...)
var qrcode = totp.qrcode(uri, function(data) {
  console.log(data.uri); // data.uri 은 QRCode 를 Base64 로 인코딩되어 반환된 것입니다. (Content-Type: image/png)
  // data.raw 는 PNG 이미지 원본 데이터
});

// 두번째 방법 (HOTP 사용시...)
var qrcode = hotp.qrcode(uri, function(data) {
  console.log(data.uri); // data.uri 은 QRCode 를 Base64 로 인코딩되어 반환된 것입니다. (Content-Type: image/png)
  // data.raw 는 PNG 이미지 원본 데이터
});

var verify = totp.verify('key', 'token'); // TOTP 토큰 (OTP 번호)를 검증합니다. (만약 정상이라면 true 를 반환, 아니라면 false 를 반환합니다)
var verify = hotp.verify('key', 'token', 'counter'); // HOTP 토큰 (OTP 번호)를 검증합니다. (만약 정상이라면 true 를 반환, 아니라면 false 를 반환합니다)
```

### 작성자: [이동인](https://github.com/donginl)
