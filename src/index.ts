import * as base32 from 'thirty-two';
import notp from 'notp';
import QRCode from 'qrcode';
import util from 'util';

class totp {
    /**
     * Generate Time One Time Password URI (otpauth://)
     *
     * @param key (OTP Key)
     * @param label (OTP Label)
     * @return OTP Auth URL
     *
     */
    create(key:string, label:string) {
        if (!key) return null;
        return util.format('otpauth://totp/%s?secret=%s', label, base32.encode(key).toString().replace(/=/g,''));
    }

    /**
     * Generate OTP QR Code
     *
     * @param uri (OTP Auth URL)
     *
     */
    async qrcode(uri:string) {
        return new Promise(async(resolve, reject) => {
          try {
            resolve(await QRCode.toDataURL(uri));
          } catch(err) {
            reject(err)
          }
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
    verify(key:string, token:string) {
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
    create(key:string, label:string) {
        if (!key) return null;
        return util.format('otpauth://hotp/%s?secret=%s', label, base32.encode(key).toString().replace(/=/g,''));
    }

    async qrcode(uri:string) {
      return new Promise(async(resolve, reject) => {
        try {
          resolve(await QRCode.toDataURL(uri));
        } catch(err) {
          reject(err)
        }
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

    verify(key:string, token:string, counter:number) {
        return !!notp.hotp.verify(token, key, {counter: counter});
    }
}

const TOTP = new totp();
const HOTP = new hotp();
export { TOTP, HOTP };