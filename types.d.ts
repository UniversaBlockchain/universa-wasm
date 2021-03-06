declare module 'universa-wasm' {
  export function encode64(data: Uint8Array): string;
  export function encode64Short(data: Uint8Array): string;
  export function decode64(encoded: string): Uint8Array;
  export function decode64Short(encoded: string): Uint8Array;
  export function encode58(data: Uint8Array): string;
  export function decode58(encoded: string): Uint8Array;

  export function textToBytes(text: string): Uint8Array;
  export function hexToBytes(hexstring: string): Uint8Array;
  export function bytesToHex(bytes: Uint8Array): string;
  export function hashId(data: Uint8Array): Promise<Uint8Array>;
  export function randomBytes(size: number): Uint8Array;
  export function crc32(data: Uint8Array): Uint8Array;

  export interface CreateKeysOpts {
    strength?: number
  }

  export interface PBKDF2Opts {
    password: string | Uint8Array,
    salt?: string | Uint8Array,
    rounds?: number,
    keyLength?: number
  }

  export function pbkdf2(sha: SHAStringType, options: PBKDF2Opts): Promise<Uint8Array>;

  export class BigInteger {
    constructor(value: any, encoding: any);
  }

  export class SHA {
    constructor(size: string | number);

    get(encoding?: string): Promise<Uint8Array>;
    get(data?: Uint8Array, encoding?: string): Promise<Uint8Array>;
    put(data: Uint8Array): Promise<void>;

    static getDigest(sha: SHAStringType, data: Uint8Array): Promise<Uint8Array>;
  }

  export class HMAC {
    constructor(sha: SHAStringType, key: Uint8Array);

    put(data: Uint8Array): Promise<void>;
  }

  export class AbstractKey {
    static readonly TYPE_PRIVATE: number;
    static readonly TYPE_PUBLIC: number;
    static readonly TYPE_PRIVATE_PASSWORD: number;
    static readonly TYPE_PRIVATE_PASSWORD_V2: number;
    static readonly FINGERPRINT_SHA256: number;
    static readonly FINGERPRINT_SHA384: number;

    static typeOf(key: Uint8Array): number;
  }

  export type SHAStringType = "sha1" | "sha256" | "sha384" | "sha512" | "sha512/256" | "sha3_256" | "sha3_384" | "sha3_512";

  export interface PrivateKeyUnpackBOSS {
    bin: Uint8Array,
    password: string
  }

  export interface PrivateKeyPackBOSS {
    rounds?: number,
    password: string
  }

  export interface PrivateKeySignOpts {
    pssHash?: SHA | HMAC | SHAStringType,
    mgf1Hash?: SHA | HMAC | SHAStringType,
    oaepHash?: SHA | HMAC | SHAStringType,
    salt?: string | Uint8Array,
    saltLength?: number,
    seed?: string | Uint8Array
  }

  export class PrivateKey {
    public publicKey: PublicKey;

    pack(options?: string | PrivateKeyPackBOSS): Promise<Uint8Array>;
    sign(data: Uint8Array, options: PrivateKeySignOpts): Promise<Uint8Array>;
    signExtended(data: Uint8Array): Promise<Uint8Array>;
    decrypt(data: Uint8Array, options?: PublicKeyEncryptOpts): Promise<Uint8Array>;

    static unpack(packed: Uint8Array, password?: string): Promise<PrivateKey>;
    static generate(options: CreateKeysOpts): Promise<PrivateKey>;
  }

  export interface PublicKeyEncryptOpts {
    pssHash?: SHA | HMAC | SHAStringType,
    mgf1Hash?: SHA | HMAC | SHAStringType,
    oaepHash?: SHA | HMAC | SHAStringType,
    salt?: string | Uint8Array,
    saltLength?: number,
    seed?: string | Uint8Array
  }

  export interface AddressOpts {
    long?: boolean,
    typeMark?: number
  }

  export class PublicKey {
    readonly shortAddress: Uint8Array;
    readonly longAddress: Uint8Array;
    readonly shortAddress58: string;
    readonly longAddress58: string;
    readonly fingerprint: Uint8Array;

    getBitStrength(): number;
    encryptionMaxLength(options?: PublicKeyEncryptOpts): number;
    pack(mode: string): Promise<Uint8Array>;
    verify(
      message: Uint8Array,
      signature: Uint8Array,
      options: PrivateKeySignOpts
    ): Promise<boolean>;
    verifyExtended(signature: Uint8Array, message: Uint8Array): Promise<any>;
    encrypt(data: Uint8Array, options?: PublicKeyEncryptOpts): Promise<Uint8Array>;

    static unpack(packed: Uint8Array): Promise<PublicKey>;
    static isValidAddress(address: Uint8Array | string): boolean;
    static readonly DEFAULT_OAEP_HASH: SHA;
    static readonly DEFAULT_MGF1_HASH: SHA;
  }

  export class Boss {
    constructor();

    dump(data: any): Uint8Array;
    load(packed: Uint8Array): any;
  }

  export namespace Boss {
    export class writer {
      constructor();

      write(data: any): void;
      get(): Uint8Array;
    }

    export class reader {
      constructor(data: Uint8Array);

      read(): any;
    }
  }

  export class SignedRecord {
    constructor(recordType: number, key: PrivateKey, payload: any, nonce?: Uint8Array);

    public recordType: number;
    public key: PrivateKey;
    public payload: any;
    public nonce: Uint8Array | null;

    static readonly RECORD_WITH_KEY: number;
    static readonly RECORD_WITH_ADDRESS: number;

    static packWithKey(key: PrivateKey, payload: any, nonce?: Uint8Array): Promise<Uint8Array>;
    static unpack(packed: Uint8Array): Promise<SignedRecord>;
  }

  export class Capsule {
    constructor();

    static sign(capsuleBinary: Uint8Array, key: PrivateKey): Uint8Array;
    static getSignatures(capsuleBinary: Uint8Array): Uint8Array[];
    static getSignatureKeys(capsuleBinary: Uint8Array): PublicKey[];
  }

  export interface KeyInfoOpts {
    algorithm: number;
    tag?: Uint8Array;
    keyLength?: number;
    prf?: number;
    rounds?: number;
    salt?: Uint8Array;
  }

  export interface PRFType {
    None: number;
    HMAC_SHA1: number;
    HMAC_SHA256: number;
    HMAC_SHA512: number;
  }

  export interface AlgorithmType {
    UNKNOWN: number;
    RSAPublic: number;
    RSAPrivate: number;
    AES256: number;
  }

  export class KeyInfo {
    constructor(params: KeyInfoOpts);

    static readonly PRF: PRFType;
    static readonly Algorithm: AlgorithmType;

    pack(): Uint8Array;
    matchType(other: KeyInfo): boolean;
    derivePassword(password: string): Promise<Uint8Array>;

    static unpack(packed: Uint8Array): KeyInfo;
  }

  export interface SymmetricKeyOpts {
    keyBytes?: Uint8Array,
    keyInfo?: KeyInfo
  }

  export class SymmetricKey {
    constructor(options?: SymmetricKeyOpts);

    pack(): Uint8Array;
    encrypt(data: Uint8Array): Uint8Array;
    decrypt(data: Uint8Array): Uint8Array;
    etaEncrypt(data: Uint8Array): Promise<Uint8Array>;
    etaDecrypt(data: Uint8Array): Promise<Uint8Array>;

    static fromPassword(password: string, rounds: number, salt?: Uint8Array): Promise<SymmetricKey>;
  }

  export class AES {
    constructor(key: Uint8Array);

    encrypt(data: Uint8Array): Uint8Array;
    decrypt(data: Uint8Array): Uint8Array;
  }
}
