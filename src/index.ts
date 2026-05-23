import { createHmac, timingSafeEqual } from "node:crypto"

const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
const digits = 6
const totpPeriodSeconds = 30
const maxTotpWindow = 10
const maxQrCodeUriLength = 2048
const tokenPattern = new RegExp(`^\\d{${digits}}$`)

/**
 * Shared methods for both {@link TotpAPI} and {@link HotpAPI}.
 */
type OtpAPI = {
  /**
   * Generates an `otpauth://` URI to register the secret with an authenticator app.
   * @param key - The shared secret (plain text; encoded to Base32 internally).
   * @param label - Account identifier shown in the authenticator (e.g. `"alice@example.com"`).
   * @returns An `otpauth://` URI string.
   * @throws {TypeError} If `key` is empty.
   */
  create(key: string, label: string): string

  /**
   * Converts an `otpauth://` URI into a Base64-encoded PNG data URL (QR code).
   * Requires the optional `qrcode` package (`pnpm add qrcode`).
   * @param uri - An `otpauth://` URI returned by `create`.
   * @returns A `data:image/png;base64,...` string ready for use in an `<img>` tag.
   * @throws {TypeError} If `uri` is not a valid `otpauth://` URI.
   * @throws {RangeError} If `uri` is too long.
   * @throws {Error} If the `qrcode` package is not installed.
   * @example
   * const dataUrl = await TOTP.qrcode(uri)
   * // "data:image/png;base64,..."
   */
  qrcode(uri: string): Promise<string>
}

/**
 * API for Time-based One-Time Password (TOTP, RFC 6238).
 * Tokens rotate every 30 seconds based on the current time.
 */
type TotpAPI = OtpAPI & {
  /**
   * Checks whether a token is valid for the current time window.
   * @param key - The shared secret used when the URI was created.
   * @param token - The 6-digit token entered by the user.
   * @param window - Number of 30-second periods to accept on either side of the current period (default `1`).
   * @returns `true` if the token matches any counter in the allowed window.
   * @throws {TypeError} If `key` is empty or `window` is not a number.
   * @throws {RangeError} If `window` is not an integer from `0` through `10`.
   * @example
   * const ok = TOTP.verify(sharedSecret, "123456")
   * const lenient = TOTP.verify(sharedSecret, "123456", 2) // ±2 periods
   */
  verify(key: string, token: string, window?: number): boolean
}

/**
 * API for HMAC-based One-Time Password (HOTP, RFC 4226).
 * Tokens are derived from an incrementing counter rather than the clock.
 */
type HotpAPI = OtpAPI & {
  /**
   * Checks whether a token is valid for a specific counter value.
   * @param key - The shared secret used when the URI was created.
   * @param token - The 6-digit token to verify.
   * @param counter - The counter value that was used to generate the token.
   * @returns `true` if the token matches the given counter.
   * @throws {TypeError} If `key` is empty or `counter` is not a number.
   * @throws {RangeError} If `counter` is not a non-negative safe integer.
   * @example
   * const ok = HOTP.verify(sharedSecret, "123456", 42)
   */
  verify(key: string, token: string, counter: number): boolean
}

/** Encodes a UTF-8 string to Base32 (RFC 4648) without padding. */
function base32Encode(input: string): string {
  let result = "",
    bits = 0,
    value = 0
  for (const byte of Buffer.from(input, "utf8")) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) result += base32Chars[(value >>> (bits -= 5)) & 31]
  }
  if (bits > 0) result += base32Chars[(value << (5 - bits)) & 31]
  return result
}

function assertNonEmptyKey(key: string): void {
  if (typeof key !== "string" || key.length === 0)
    throw new TypeError("key must be a non-empty string")
}

function assertOtpAuthUri(uri: string): void {
  if (typeof uri !== "string")
    throw new TypeError("uri must be an otpauth URI string")
  if (uri.length > maxQrCodeUriLength)
    throw new RangeError(
      `uri must be ${maxQrCodeUriLength} characters or fewer`,
    )

  let parsedUri: URL
  try {
    parsedUri = new URL(uri)
  } catch {
    throw new TypeError("uri must be a valid otpauth URI")
  }

  if (parsedUri.protocol !== "otpauth:")
    throw new TypeError("uri must use the otpauth protocol")
  if (parsedUri.hostname !== "totp" && parsedUri.hostname !== "hotp")
    throw new TypeError("uri must be an otpauth totp or hotp URI")
  if (!parsedUri.searchParams.get("secret"))
    throw new TypeError("uri must include a secret parameter")
}

function createOtpAuthUri(
  type: "totp" | "hotp",
  key: string,
  label: string,
): string {
  assertNonEmptyKey(key)
  const params: Record<string, string> = { secret: base32Encode(key) }
  if (type === "hotp") params.counter = "0"
  const searchParams = new URLSearchParams(params)
  return `otpauth://${type}/${encodeURIComponent(label)}?${searchParams}`
}

async function createQrCode(uri: string): Promise<string> {
  assertOtpAuthUri(uri)
  let qrCode: typeof import("qrcode")
  try {
    qrCode = await import("qrcode")
  } catch {
    throw new Error(
      'qrcode is not installed. Run "pnpm add qrcode" to use this feature.',
    )
  }
  return qrCode.toDataURL(uri)
}

function verifyToken(key: string, token: string, counter: number): boolean {
  if (typeof token !== "string") return false
  if (!tokenPattern.test(token)) return false
  return timingSafeEqual(
    Buffer.from(computeHotp(key, counter)),
    Buffer.from(token),
  )
}

/**
 * Computes an HOTP value per RFC 4226 §5 (HMAC-SHA1 + dynamic truncation).
 * @param key - Plain-text secret used as the HMAC-SHA1 key.
 * @param counter - 8-byte big-endian counter value.
 * @returns Zero-padded decimal string of length {@link digits}.
 */
function computeHotp(key: string, counter: number): string {
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac("sha1", key).update(buf).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  return (code % 10 ** digits).toString().padStart(digits, "0")
}

/**
 * Time-based One-Time Password helpers (RFC 6238).
 * @example
 * import { TOTP } from "quickotp"
 * const uri = TOTP.create(sharedSecret, "alice@example.com")
 * const ok = TOTP.verify(sharedSecret, userInput)
 */
export const TOTP = {
  create: (key, label) => createOtpAuthUri("totp", key, label),
  qrcode: createQrCode,
  verify(key: string, token: string, window = 1): boolean {
    assertNonEmptyKey(key)
    if (typeof window !== "number" || Number.isNaN(window))
      throw new TypeError("window must be a number")
    if (!Number.isInteger(window) || window < 0 || window > maxTotpWindow)
      throw new RangeError(
        `window must be an integer from 0 through ${maxTotpWindow}`,
      )
    const counter = Math.floor(Date.now() / 1000 / totpPeriodSeconds)
    for (let i = -window; i <= window; i++)
      if (counter + i >= 0 && verifyToken(key, token, counter + i)) return true
    return false
  },
} satisfies TotpAPI

/**
 * HMAC-based One-Time Password helpers (RFC 4226).
 * @example
 * import { HOTP } from "quickotp"
 * const uri = HOTP.create(sharedSecret, "alice@example.com")
 * const ok = HOTP.verify(sharedSecret, userInput, counter)
 */
export const HOTP = {
  create: (key, label) => createOtpAuthUri("hotp", key, label),
  qrcode: createQrCode,
  verify(key: string, token: string, counter: number): boolean {
    assertNonEmptyKey(key)
    if (typeof counter !== "number" || Number.isNaN(counter))
      throw new TypeError("counter must be a number")
    if (!Number.isSafeInteger(counter) || counter < 0)
      throw new RangeError("counter must be a non-negative safe integer")
    return verifyToken(key, token, counter)
  },
} satisfies HotpAPI
