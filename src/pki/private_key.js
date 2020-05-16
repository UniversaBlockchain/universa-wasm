var Module = Module || require('../vendor/wasm/wrapper');

const Boss = require('../boss/protocol');
const utils = require('../utils');
const helpers = require('./helpers');
const PublicKey = require('./public_key');
const SHA = require('../hash/sha');
const HMAC = require('../hash/hmac');
const pbkdf2 = require('./pbkdf2');
const cipher = require('../cipher');
const AbstractKey = require('./abstract_key');
const SymmetricKey = require('./symmetric_key');
const KeyInfo = require('./key_info');
const ExtendedSignature = require('./extended_signature');

const {
  BigInteger,
  bigIntToByteArray,
  byteArrayToBigInt,
  byteStringToArray,
  randomBytes,
  concatBytes,
  crc32,
  textToHex,
  hexToBytes,
  encode64
} = utils;

const { AESCTRTransformer } = cipher;

const { ONE: one } = BigInteger;
const { wrapOptions, getMaxSalt, normalizeOptions } = helpers;

module.exports = class PrivateKey extends AbstractKey {
  constructor(key) {
    super();

    this.key = key;
    this.publicKey = PublicKey.fromPrivate(key);
  }

  delete() {
    this.key.delete();
  }

  getN() { return this.publicKey.getN(); }
  getE() { return this.publicKey.getE(); }
  getP() { return this.key.get_p(); }
  getQ() { return this.key.get_q(); }
  getBitStrength() { return this.publicKey.getBitStrength(); }
  get fingerprint() {
    return this.publicKey.fingerprint;
  }
  async sign(data, options = {}) {
    const self = this;
    const hashType = SHA.wasmType(options.pssHash || 'sha1');
    const mgf1Type = SHA.wasmType(options.mgf1Hash || 'sha1');
    let saltLength = -1;
    if (typeof options.saltLength === 'number') saltLength = options.saltLength;

    return new Promise(resolve => {
      const cb = res => resolve(new Uint8Array(res));

      if (options.salt)
        self.key.signWithCustomSalt(data, hashType, mgf1Type, salt, cb);
      else
        self.key.sign(data, hashType, mgf1Type, saltLength, cb);
    });
  }

  async signExtended(data) {
    const self = this;
    const pub = this.publicKey;
    const dataHash = new SHA('512');
    const fingerprint = pub.fingerprint;
    const sha512Digest = await dataHash.get(data);
    const publicPacked = await pub.packed();
    const boss = new Boss();
    const targetSignature = boss.dump({
      'key': fingerprint,
      'sha512': sha512Digest,
      'created_at': new Date(),
      'pub_key': publicPacked
    });


    const signature = await self.sign(targetSignature, {
      pssHash: 'sha512',
      mgf1Hash: 'sha1'
    });

    return boss.dump({
      'exts': targetSignature,
      'sign': signature
    });
  }

  async decrypt(data, options = {}) {
    const self = this;
    const oaepHash = SHA.wasmType(options.oaepHash || 'sha1');

    return new Promise(resolve => {
      self.key.decrypt(data, oaepHash, (res) => {
        resolve(new Uint8Array(res));
      });
    });
  }

  async pack(options) {
    return this.packBOSS(options);
  }

  async packBOSS(options) {
    const self = this;

    return new Promise(resolve => {
      if (!options)
        self.key.pack(bin => resolve(new Uint8Array(bin)));
      else {
        const password = options.password || options;
        const rounds = options.rounds || 160000;

        self.key.packWithPassword(password, rounds, (err, packed) => {
          if (err === '') resolve(new Uint8Array(packed));
          else reject(err);
        });
      }
    });
  }

  static async unpack(options) {
    if (options.q && options.p)
      return new PrivateKey(await this.unpackExponents(options));

    return new PrivateKey(await this.unpackBOSS(options));
  }

  static async unpackBOSS(options) {
    const self = this;

    await Module.isReady;

    return new Promise(resolve => {
      if (!options.password) return resolve(new Module.PrivateKeyImpl(options));

      const { bin, password } = options;

      Module.PrivateKeyImpl.unpackWithPassword(bin, password, (err, key) => {
        if (err === "") resolve(key);
        else reject(err);
      });
    });
  }

  static async unpackExponents(options) {
    const boss = new Boss();
    const { e, p, q } = options;

    return this.unpackBOSS(boss.dump([
      AbstractKey.TYPE_PRIVATE,
      bigIntToByteArray(new BigInteger(e, 16)),
      bigIntToByteArray(new BigInteger(p, 16)),
      bigIntToByteArray(new BigInteger(q, 16))
    ]));
  }

  static async generate(options) {
    const { strength } = options;

    await Module.isReady;

    return new Promise(resolve => {
      Module.PrivateKeyImpl.generate(strength, key =>
        resolve(new PrivateKey(key))
      );
    });
  }
}

function toBOSS(instance, options) {
  if (options) return toBOSSPassword(instance, options);

  const { key } = instance;

  const boss = new Boss();
  const { e, p, q } = key;

  return boss.dump([
    AbstractKey.TYPE_PRIVATE,
    bigIntToByteArray(e),
    bigIntToByteArray(p),
    bigIntToByteArray(q)
  ]);
}

function fromBOSS(dump) {
  if (dump.password) return fromBOSSPassword(dump);

  return new Module.PrivateKeyImpl(dump);
}

/**
 * Restores private key exponents from e, p, q
 *
 * @param {Object} exps - dict of exponents passed to private key.
 *                             Exponents must be in BigInteger format
 */
function fromExponents(exps) {
  const { e, p, q } = exps;

  const n = exps.n || p.multiply(q);
  const d = exps.d || e.modInverse(p.subtract(one).multiply(q.subtract(one)));
  const dP = exps.dP || d.mod(p.subtract(one));
  const dQ = exps.dQ || d.mod(q.subtract(one));
  const qInv = exps.qInv || q.modInverse(p);

  return rsa.setPrivateKey(n, e, d, p, q, dP, dQ, qInv);
}

function toExponents(instance) {
  return instance.params;
}
