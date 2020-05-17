var Module = Module || require('../vendor/wasm/wrapper');
const { bytesToHex } = require('../utils/bytes');

const StringTypes = {
  "sha1": 0,
  "sha256": 1,
  "sha512": 2,
  "sha3_256": 3,
  "sha3_384": 4,
  "sha3_512": 5
};

class SHA {
  constructor(hashType) {
    this.hashType = hashType;
    const wasmTpe = SHA.wasmType(hashType);
    const tpe = typeof wasmTpe === 'number' ? wasmTpe : hashType;
    this.wasmType = tpe;
    this.hash = SHA.init(this.wasmType);
    this.empty = true;
  }

  getSync() {
    return new Module.DigestImpl(this.wasmType);
  }

  async delete() {
    (await this.hash).delete();
  }

  async update(data) {
    this.empty = false;
    (await this.hash).update(data);
  }

  async put(data) {
    this.update(data);
  }

  async doFinal() {
    (await this.hash).doFinal();
  }

  getDigestSize() {
    return (this.getSync()).getDigestSize();
  }

  async getDigest(encoding) {
    const hash = await this.hash;

    return new Promise((resolve, reject) => {
      hash.getDigest(res => {
        const bytes = new Uint8Array(res);

        if (encoding === 'hex') resolve(bytesToHex(bytes));
        else resolve(bytes);
      });
    });
  }

  async get(data, encoding) {
    if (typeof data !== 'string' || this.empty) await this.update(data);
    else encoding = data;

    // if (data) this.update(data);

    await this.doFinal();
    return this.getDigest(encoding);
  }

  static async hashId(data) {
    await Module.isReady;

    return new Promise(resolve => {
      Module.calcHashId(data, res => resolve(new Uint8Array(res)));
    });
  }

  static wasmType(stringType) {
    if (typeof stringType !== 'string') return false;

    const lower = stringType.toLowerCase();
    let tpe = SHA.StringTypes[lower];
    if (typeof tpe !== 'number') tpe = SHA.StringTypes[`sha${lower}`];

    if (typeof tpe !== 'number') return false;

    return tpe;
  }

  static async init(wasmType) {
    await Module.isReady;

    return new Module.DigestImpl(wasmType);
  }

  static async getDigest(hashType, data) {
    const sha = new SHA(hashType);

    return sha.get(data);
  }
}

SHA.StringTypes = StringTypes;

module.exports = SHA;
