import { createHmac } from "node:crypto"

const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
const defaultDigits = 6
const totpPeriodSeconds = 30

type OtpType = "totp" | "hotp"

type TotpAPI = {
  create(key: string, label: string): string
  qrcode(uri: string): Promise<string>
  verify(key: string, token: string, window?: number): boolean
}

type HotpAPI = {
  create(key: string, label: string): string
  qrcode(uri: string): Promise<string>
  verify(key: string, token: string, counter: number): boolean
}

function base32Encode(input: string): string {
  const buffer = Buffer.from(input, "utf8")
  let result = ""
  let bits = 0
  let value = 0
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      result += base32Chars[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) {
    result += base32Chars[(value << (5 - bits)) & 31]
  }
  return result
}

function assertNonEmptyKey(key: string): void {
  if (typeof key !== "string" || key.length === 0) {
    throw new TypeError("key must be a non-empty string")
  }
}

function assertNonNegativeSafeInteger(value: number, name: string): void {
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new TypeError(`${name} must be a number`)
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`)
  }
}

function assertNonNegativeInteger(value: number, name: string): void {
  if (typeof value !== "number" || Number.isNaN(value)) {
    throw new TypeError(`${name} must be a number`)
  }
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative integer`)
  }
}

function createOtpAuthUri(type: OtpType, key: string, label: string): string {
  assertNonEmptyKey(key)
  const searchParams = new URLSearchParams({ secret: base32Encode(key) })
  return `otpauth://${type}/${encodeURIComponent(label)}?${searchParams}`
}

async function createQrCode(uri: string): Promise<string> {
  let qrCode: typeof import("qrcode")
  try {
    qrCode = (await import("qrcode")) as typeof import("qrcode")
  } catch {
    throw new Error(
      'qrcode is not installed. Run "pnpm add qrcode" to use this feature.',
    )
  }
  return qrCode.toDataURL(uri)
}

function computeHotp(
  key: string,
  counter: number,
  digits = defaultDigits,
): string {
  assertNonNegativeSafeInteger(counter, "counter")
  const counterBuffer = Buffer.alloc(8)
  counterBuffer.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac("sha1", key).update(counterBuffer).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const code =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  return (code % 10 ** digits).toString().padStart(digits, "0")
}

const totp: TotpAPI = {
  create(key: string, label: string): string {
    return createOtpAuthUri("totp", key, label)
  },

  async qrcode(uri: string): Promise<string> {
    return createQrCode(uri)
  },

  verify(key: string, token: string, window = 1): boolean {
    const windowSize = window
    assertNonNegativeInteger(windowSize, "window")
    const counter = Math.floor(Date.now() / 1000 / totpPeriodSeconds)
    for (let i = -windowSize; i <= windowSize; i++) {
      const candidateCounter = counter + i
      if (candidateCounter < 0) continue
      if (computeHotp(key, candidateCounter) === token) return true
    }
    return false
  },
}

const hotp: HotpAPI = {
  create(key: string, label: string): string {
    return createOtpAuthUri("hotp", key, label)
  },

  async qrcode(uri: string): Promise<string> {
    return createQrCode(uri)
  },

  verify(key: string, token: string, counter: number): boolean {
    return computeHotp(key, counter) === token
  },
}

export { hotp as HOTP, totp as TOTP }
