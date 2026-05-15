import { describe, it, before, after } from "node:test"
import assert from "node:assert/strict"
import { TOTP, HOTP } from "../src/index.js"

// RFC 4226 Appendix D — HOTP test vectors
// Key: "12345678901234567890" (ASCII), counter: 0-9
describe("HOTP — RFC 4226 Appendix D vectors", () => {
  const RFC_KEY = "12345678901234567890"
  const vectors = [
    { counter: 0, token: "755224" },
    { counter: 1, token: "287082" },
    { counter: 2, token: "359152" },
    { counter: 3, token: "969429" },
    { counter: 4, token: "338314" },
    { counter: 5, token: "254676" },
    { counter: 6, token: "287922" },
    { counter: 7, token: "162583" },
    { counter: 8, token: "399871" },
    { counter: 9, token: "520489" },
  ]

  for (const { counter, token } of vectors) {
    it(`counter=${counter} → ${token}`, () => {
      assert.equal(HOTP.verify(RFC_KEY, token, counter), true)
    })
  }
})

// RFC 6238 — TOTP via HOTP at specific counter values
// timestamp 59 → counter = floor(59/30) = 1 → HOTP(key, 1) = "287082"
// timestamp 1111111111 → counter = floor(1111111111/30) = 37037037
describe("TOTP — RFC 6238 derived via Date.now mock", () => {
  const RFC_KEY = "12345678901234567890"
  let originalDateNow: typeof Date.now
  const invalidWindows: Array<[number, typeof TypeError | typeof RangeError]> = [
    [Number.NaN, TypeError],
    [-1, RangeError],
    [1.5, RangeError],
  ]

  before(() => {
    originalDateNow = Date.now
  })

  after(() => {
    Date.now = originalDateNow
  })

  it("timestamp=59 (counter=1) verifies correctly", () => {
    Date.now = () => 59 * 1000
    // counter = 1, RFC 4226 vector: "287082"
    assert.equal(TOTP.verify(RFC_KEY, "287082"), true)
  })

  it("window drift: adjacent counter is also valid", () => {
    // counter = 1 at timestamp 59; window=1 checks counters 0,1,2
    // counter 0 → "755224"
    Date.now = () => 59 * 1000
    assert.equal(TOTP.verify(RFC_KEY, "755224"), true)
  })

  it("skips negative candidate counters near epoch start", () => {
    Date.now = () => 0
    assert.equal(TOTP.verify(RFC_KEY, "755224"), true)
  })

  it("wrong token returns false", () => {
    Date.now = () => 59 * 1000
    assert.equal(TOTP.verify(RFC_KEY, "000000"), false)
  })

  for (const [window, error] of invalidWindows) {
    it(`throws ${error.name} for invalid window=${window}`, () => {
      assert.throws(() => TOTP.verify(RFC_KEY, "287082", window), error)
    })
  }
})

// Base32 encoding — RFC 4648 §10 test vectors (no padding)
describe("Base32 — RFC 4648 vectors", () => {
  // Test indirectly via create() URI secret extraction
  const vectors: Array<[string, string]> = [
    ["f", "MY"],
    ["fo", "MZXQ"],
    ["foo", "MZXW6"],
    ["foob", "MZXW6YQ"],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI"],
  ]

  for (const [input, expected] of vectors) {
    it(`base32("${input}") = "${expected}"`, () => {
      const uri = TOTP.create(input, "test")
      const secret = new URL(uri).searchParams.get("secret")
      assert.equal(secret, expected)
    })
  }
})

// URI construction
describe("URI construction", () => {
  const cases = [
    { api: TOTP, scheme: "totp" },
    { api: HOTP, scheme: "hotp" },
  ]

  for (const { api, scheme } of cases) {
    it(`${scheme.toUpperCase()} URI has correct scheme and parameters`, () => {
      const uri = api.create("secret", "My App")
      assert.equal(uri, `otpauth://${scheme}/My%20App?secret=ONSWG4TFOQ`)
      assert.ok(uri.startsWith(`otpauth://${scheme}/`))
      assert.ok(uri.includes("secret=ONSWG4TFOQ")) // base32("secret")
      assert.ok(uri.includes("My%20App")) // URL-encoded label
    })
  }

  it("throws TypeError for empty key", () => {
    for (const { api } of cases) {
      assert.throws(() => api.create("", "label"), TypeError)
    }
  })
})

describe("HOTP counter validation", () => {
  const invalidCounters: Array<[number, typeof TypeError | typeof RangeError]> = [
    [Number.NaN, TypeError],
    [-1, RangeError],
    [1.5, RangeError],
    [Number.MAX_SAFE_INTEGER + 1, RangeError],
  ]

  for (const [counter, error] of invalidCounters) {
    it(`throws ${error.name} for invalid counter=${counter}`, () => {
      assert.throws(() => HOTP.verify("secret", "123456", counter), error)
    })
  }
})

// qrcode peer dep — works when installed
describe("qrcode — optional peer dependency", () => {
  it("returns a data URL when qrcode is installed", async () => {
    const uri = TOTP.create("secret", "test")
    const dataUrl = await TOTP.qrcode(uri)
    assert.ok(dataUrl.startsWith("data:image/png;base64,"))
  })
})
