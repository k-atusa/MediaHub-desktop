// test793b : USAG-Lib bencrypt
// !!! JS version is  not designed for big data !!!
const isNode = (typeof window === 'undefined');
const deps = {
    crypto: null,
    argon2: null,
    sha3256: null,
    sha3512: null,
    noble: null,
    ml_kem1024: null,
    ml_dsa87: null
};
if (isNode) {
    try {
        const nodeCrypto = await import('crypto');
        deps.crypto = nodeCrypto.default || nodeCrypto;
    } catch (e) { console.error('crypto module not found'); }

    try {
        const nodeSha3 = await import('js-sha3');
        deps.sha3256 = nodeSha3.sha3_256;
        deps.sha3512 = nodeSha3.sha3_512;
    } catch (e) { console.error('js-sha3 module not installed'); }

    try {
        const nodeArgon2 = await import('argon2');
        deps.argon2 = nodeArgon2.default || nodeArgon2;
    } catch (e) { console.error('argon2 module not installed'); }

    try {
        const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem');
        const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa');
        deps.ml_kem1024 = ml_kem1024;
        deps.ml_dsa87 = ml_dsa87;
    } catch (e) { console.error('@noble/post-quantum module not installed'); }

} else {
    if (typeof self !== 'undefined' && self.crypto) { deps.crypto = self.crypto; }
    else if (typeof window !== 'undefined' && window.crypto) { deps.crypto = window.crypto; }
    else { console.error('web crypto api not found'); }

    try {
        const webSha3 = (await import('https://esm.sh/js-sha3@0.9.3')).default;
        deps.sha3256 = webSha3.sha3_256;
        deps.sha3512 = webSha3.sha3_512;
    } catch (e) { console.error('sha3 module not installed'); }

    try {
        const webArgon2 = (await import('https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js/+esm')).default;
        deps.argon2 = webArgon2;
    } catch (e) { console.error('argon2 module not installed'); }

    try {
        const webNoble = await import('https://esm.sh/@noble/curves@1.4.0/ed448');
        deps.noble = {
            x448: webNoble.x448,
            ed448: webNoble.ed448
        };
    } catch (e) { console.error('@noble/curves module not installed'); }

    try {
        const { ml_kem1024 } = await import('https://esm.sh/@noble/post-quantum/ml-kem');
        const { ml_dsa87 } = await import('https://esm.sh/@noble/post-quantum/ml-dsa');
        deps.ml_kem1024 = ml_kem1024;
        deps.ml_dsa87 = ml_dsa87;
    } catch (e) { console.error('@noble/post-quantum module not installed via CDN'); }
}

// ========== Helpers ==========
export let DUMMY = null;
function zeroize(arr) {
    if (arr && arr.byteLength > 0 && typeof arr.fill === 'function') {
        arr.fill(0);
        globalThis.DUMMY_CRYPTO_VOLATILE = arr;
    }
}

function toU8(data) {
    if (typeof data === 'string') return new TextEncoder().encode(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    return data;
}

/**
 * @param {Uint8Array} g - Base IV 12B
 * @param {number} c - Counter
 * @returns {Uint8Array} - Modified IV 12B
 */
function mkiv(g, c) {
    const iv = new Uint8Array(g); // Copy input
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setBigUint64(0, BigInt(c), true); // Little Endian
    const counterBytes = new Uint8Array(counterBuf);
    for (let i = 0; i < 8; i++) {
        iv[4 + i] ^= counterBytes[i];
    }
    return iv;
}

function hmac_sha3_256(key, msg) {
    const B = 136; // Block size for SHA3-256
    let k = toU8(key);
    const m = toU8(msg);

    if (k.length > B) {
        k = SHA3256(k);
    }
    if (k.length < B) {
        const newK = new Uint8Array(B);
        newK.set(k);
        k = newK;
    }

    const o_key_pad = new Uint8Array(B);
    const i_key_pad = new Uint8Array(B);
    for (let i = 0; i < B; i++) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    const innerData = new Uint8Array(B + m.length);
    innerData.set(i_key_pad);
    innerData.set(m, B);
    const innerHash = SHA3256(innerData);

    const outerData = new Uint8Array(B + innerHash.length);
    outerData.set(o_key_pad);
    outerData.set(innerHash, B);
    const result = SHA3256(outerData);

    zeroize(i_key_pad);
    zeroize(o_key_pad);
    zeroize(innerData);
    zeroize(outerData);
    return result;
}

function hmac_sha3_512(key, msg) {
    const B = 72; // Block size for SHA3-512 (rate = 576 bits = 72 bytes)
    let k = toU8(key);
    const m = toU8(msg);

    // 1. Key reduction / padding
    if (k.length > B) {
        k = SHA3512(k); // Key is too long, hash it
    }
    if (k.length < B) {
        const newK = new Uint8Array(B);
        newK.set(k);
        k = newK; // Zero padding
    }

    // 2. Inner and Outer pads
    const o_key_pad = new Uint8Array(B);
    const i_key_pad = new Uint8Array(B);
    for (let i = 0; i < B; i++) {
        o_key_pad[i] = k[i] ^ 0x5c;
        i_key_pad[i] = k[i] ^ 0x36;
    }

    // 3. Inner hash: H(i_key_pad || msg)
    const innerData = new Uint8Array(B + m.length);
    innerData.set(i_key_pad);
    innerData.set(m, B);
    const innerHash = SHA3512(innerData);

    // 4. Outer hash: H(o_key_pad || innerHash)
    const outerData = new Uint8Array(B + innerHash.length);
    outerData.set(o_key_pad);
    outerData.set(innerHash, B);
    const result = SHA3512(outerData);

    zeroize(i_key_pad);
    zeroize(o_key_pad);
    zeroize(innerData);
    zeroize(outerData);
    return result
}

/**
 * genkey: HMAC-SHA3-512 based key generation
 * @param {Uint8Array} data 
 * @param {string} lbl 
 * @param {number} size 
 * @returns {Uint8Array}
 */
export function genkey(data, lbl, size) {
    const digest = hmac_sha3_512(data, lbl);
    if (size > digest.length) {
        throw new Error("key size too large");
    }
    return digest.slice(0, size);
}

export class TestReader {
    constructor(u8Array) {
        this.data = u8Array; // Uint8Array
        this.pos = 0;
    }
    async read(size) {
        if (this.pos >= this.data.length) {
            return new Uint8Array(0); // EOF
        }
        const end = Math.min(this.pos + size, this.data.length);
        const chunk = this.data.slice(this.pos, end);
        this.pos = end;
        return chunk;
    }
}

export class TestWriter {
    constructor() {
        this.chunks = [];
        this.length = 0;
    }
    async write(chunk) {
        if (chunk && chunk.length > 0) {
            const c = new Uint8Array(chunk);
            this.chunks.push(c);
            this.length += c.length;
        }
    }
    getValue() {
        const res = new Uint8Array(this.length);
        let offset = 0;
        for (const c of this.chunks) {
            res.set(c, offset);
            offset += c.length;
        }
        return res;
    }
}

// ========== Basic Functions ==========
/**
 * random: Generate secure random bytes
 * @param {number} size 
 * @returns {Uint8Array}
 */
export function Random(size) {
    if (isNode) {
        return deps.crypto.randomBytes(size);
    } else {
        const buf = new Uint8Array(size);
        deps.crypto.getRandomValues(buf);
        return buf;
    }
}

/**
 * sha3256
 * @param {Uint8Array|string} data 
 * @returns {Uint8Array}
 */
export function SHA3256(data) {
    return new Uint8Array(deps.sha3256.create().update(data).arrayBuffer());
}

/**
 * sha3512
 * @param {Uint8Array|string} data 
 * @returns {Uint8Array}
 */
export function SHA3512(data) {
    return new Uint8Array(deps.sha3512.create().update(data).arrayBuffer());
}

/**
 * hmac_sha3_256
 * @param {Uint8Array|string} key
 * @param {Uint8Array|string} data
 * @returns {Uint8Array}
 */
export function HMAC3256(key, data) {
    return hmac_sha3_256(key, data);
}

/**
 * hmac_sha3_512
 * @param {Uint8Array|string} key
 * @param {Uint8Array|string} data
 * @returns {Uint8Array}
 */
export function HMAC3512(key, data) {
    return hmac_sha3_512(key, data);
}

// ========== Data Masker ==========
export class Masker {
    static #instance = null; // singleton
    static PRIME_CANDIDATES = [
        15485863, 32452843, 86028121, 104395301,
        179424673, 228017633, 236887691, 345098717,
        413158511, 481230491, 563117203, 693240851,
        715225741, 812349821, 882046271, 999999937
    ];

    constructor(poolSizeMb = 8) {
        if (Masker.#instance) {
            return Masker.#instance;
        }
        this._initialize(poolSizeMb);
        Masker.#instance = this;
    }

    _initialize(poolSizeMb) {
        this.POOL_SIZE = poolSizeMb * 1048576;
        this.pool = new Uint8Array(this.POOL_SIZE);
        for (let i = 0; i < this.POOL_SIZE; i += 32768) {
            this.pool.set(Random(32768), i);
        }
        this.prime = Masker.PRIME_CANDIDATES[Random(1)[0] % 16];
    }

    /**
    * XOR Masking
    * @param {Uint8Array} data
    * @returns {Uint8Array}
    */
    XOR(data) {
        const L = data.length;
        if (L === 0) return data;
        if (L === 1) {
            const result = new Uint8Array(1);
            result[0] = data[0] ^ this.pool[this.prime % this.POOL_SIZE];
            return result;
        }
        if (L > this.POOL_SIZE) {
            throw new Error(`Data ${L} exceeds Pool ${this.POOL_SIZE}`);
        }
        const mid = Math.floor(L / 2);
        let left = data.slice(0, mid);
        let right = data.slice(mid);

        // 5-Round Feistel Network
        for (let round = 0; round < 5; round++) {
            let seed = 0;
            for (let i = 0; i < right.length; i++) {
                seed = (seed + right[i] * (i + 1)) % this.POOL_SIZE;
            }
            let new_left = new Uint8Array(left.length);
            for (let i = 0; i < left.length; i++) {
                const poolIdx = (seed + i * this.prime) % this.POOL_SIZE;
                new_left[i] = left[i] ^ this.pool[poolIdx];
            }
            left = right;
            right = new_left;
        }

        const finalResult = new Uint8Array(L);
        finalResult.set(right, 0);
        finalResult.set(left, right.length);
        return finalResult; // re-order for odd length
    }
}

// ========== Hash Function Master ==========
export class HashMaster {
    /**
     * @param {string} algo
     * @param {number} hashSize 
     * @param {number} keySize 
     */
    constructor(algo, hashSize = 32, keySize = 32) {
        if (!["sha3", "arg2low", "arg2st"].includes(algo)) {
            throw new Error(`Unsupported algorithm: ${algo}`);
        }
        this.algo = algo;
        this.hashSize = hashSize;
        this.keySize = keySize;
    }

    /**
     * KDF
     * @param {Uint8Array|string} pw 
     * @param {Uint8Array|string} salt 
     * @returns {Promise<[Uint8Array, Uint8Array]>} [PW storage, user key]
     */
    async KDF(pw, salt) {
        let lblStore = "";
        let lblKeygen = "";
        let master = null;
        const pwBuf = toU8(pw);
        const saltBuf = toU8(salt);

        if (this.algo === "sha3") {
            lblStore = "PWHASH_SHA3";
            lblKeygen = "KEYGEN_SHA3";
            const combined = new Uint8Array(saltBuf.length + pwBuf.length); // merge buffers
            combined.set(saltBuf, 0);
            combined.set(pwBuf, saltBuf.length);
            master = SHA3512(combined);
            zeroize(combined);

        } else if (this.algo === "arg2low") {
            lblStore = "PWHASH_ARG2LOW";
            lblKeygen = "KEYGEN_ARG2LOW";
            master = await argon2low(pwBuf, saltBuf);

        } else if (this.algo === "arg2st") {
            lblStore = "PWHASH_ARG2ST";
            lblKeygen = "KEYGEN_ARG2ST";
            master = await argon2st(pwBuf, saltBuf);

        } else {
            return [null, null];
        }

        const storeKey = genkey(master, lblStore, this.hashSize);
        const userKey = genkey(master, lblKeygen, this.keySize);
        zeroize(master);
        return [storeKey, userKey];
    }
}

// ========== Hash Functions ==========
async function argon2low(pw, salt) {
    const pwBuf = toU8(pw);
    const saltBuf = toU8(salt);
    const type = isNode ? deps.argon2.argon2id : deps.argon2.Argon2id;

    if (isNode) {
        const options = {
            type: type || 2,
            timeCost: 4,
            memoryCost: 65536,
            parallelism: 8,
            hashLength: 64,
            raw: true,
            salt: saltBuf
        };
        const hash = await deps.argon2.hash(pwBuf, options);
        return new Uint8Array(hash);
    } else {
        const options = {
            pass: pwBuf,
            salt: saltBuf,
            type: type || 2,
            time: 4,
            mem: 65536,
            parallelism: 8,
            hashLen: 64
        };
        const res = await deps.argon2.hash(options);
        return new Uint8Array(res.hash);
    }
}

async function argon2st(pw, salt) {
    const pwBuf = toU8(pw);
    const saltBuf = toU8(salt);
    const type = isNode ? deps.argon2.argon2id : deps.argon2.Argon2id;

    if (isNode) {
        const options = {
            type: type || 2,
            timeCost: 3,
            memoryCost: 262144,
            parallelism: 6,
            hashLength: 64,
            raw: true,
            salt: saltBuf
        };
        const hash = await deps.argon2.hash(pwBuf, options);
        return new Uint8Array(hash);
    } else {
        const options = {
            pass: pwBuf,
            salt: saltBuf,
            type: type || 2,
            time: 3,
            mem: 262144,
            parallelism: 6,
            hashLen: 64
        };
        const res = await deps.argon2.hash(options);
        return new Uint8Array(res.hash);
    }
}

// ========== Symmetric Encryption Master ==========
export class SymMaster {
    /**
     * @param {string} algo - "gcm1" or "gcmx1"
     * @param {Uint8Array} key - 32 bytes AES-256 Key
     */
    constructor(algo, key) {
        this.mask = new Masker();
        this.key = this.mask.XOR(toU8(key)); // saved as XOR masked
        if (algo === "gcm1" || algo === "gcmx1") {
            this.algo = algo;
            this.worker = new AES1();
            if (this.key.length !== 32) {
                throw new Error("Key length must be 32 bytes");
            }
        } else {
            throw new Error(`Unsupported algorithm: ${algo}`);
        }
    }

    /**
     * Calculate expected output size
     * @param {number} size 
     * @returns {number}
     */
    AfterSize(size) {
        if (this.algo === "gcm1") {
            return size + 28;
        } else if (this.algo === "gcmx1") {
            const chunkSize = 1048576;
            let c = Math.floor(size / chunkSize) + 1;
            if (size !== 0 && size % chunkSize === 0) {
                c -= 1;
            }
            return size + 12 + (16 * c);
        }
        return 0;
    }

    Processed() {
        return this.worker.processed();
    }

    /**
     * Encrypt binary data (Memory)
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>}
     */
    async EnBin(data) {
        const d = toU8(data);
        const key = this.mask.XOR(this.key);
        if (this.algo === "gcm1") {
            const res = await this.worker.enAESGCM(key, d);
            zeroize(key);
            return res;
        } else if (this.algo === "gcmx1") {
            const reader = new TestReader(d);
            const writer = new TestWriter();
            await this.worker.enAESGCMx(key, reader, d.length, writer, 1048576);
            zeroize(key);
            return writer.getValue();
        }
    }

    /**
     * Decrypt binary data (Memory)
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>}
     */
    async DeBin(data) {
        const d = toU8(data);
        const key = this.mask.XOR(this.key);
        if (this.algo === "gcm1") {
            const res = await this.worker.deAESGCM(key, d);
            zeroize(key);
            return res;
        } else if (this.algo === "gcmx1") {
            const reader = new TestReader(d);
            const writer = new TestWriter();
            await this.worker.deAESGCMx(key, reader, d.length, writer, 1048576);
            zeroize(key);
            return writer.getValue();
        }
    }

    /**
     * Encrypt Stream/File
     * @param {Object} src - Must have async read(size)
     * @param {number} size - Total size
     * @param {Object} dst - Must have async write(chunk)
     */
    async EnFile(src, size, dst) {
        const key = this.mask.XOR(this.key);
        if (this.algo === "gcm1") {
            const data = await src.read(size);
            const enc = await this.worker.enAESGCM(key, data);
            await dst.write(enc);
        } else if (this.algo === "gcmx1") {
            await this.worker.enAESGCMx(key, src, size, dst, 1048576);
        }
        zeroize(key);
    }

    /**
     * Decrypt Stream/File
     * @param {Object} src - Must have async read(size)
     * @param {number} size - Total size
     * @param {Object} dst - Must have async write(chunk)
     */
    async DeFile(src, size, dst) {
        const key = this.mask.XOR(this.key);
        if (this.algo === "gcm1") {
            const data = await src.read(size);
            const dec = await this.worker.deAESGCM(key, data);
            await dst.write(dec);
        } else if (this.algo === "gcmx1") {
            await this.worker.deAESGCMx(key, src, size, dst, 1048576);
        }
        zeroize(key);
    }
}

// AES Encryption
class AES1 {
    constructor() {
        this._processed = 0;
    }

    processed() {
        return this._processed;
    }

    /**
     * enAESGCM: Simple AES-GCM Encryption
     * @param {Uint8Array} key - 32 bytes Key
     * @param {Uint8Array} data 
     * @returns {Promise<Uint8Array>} IV(12) + ciphertext + tag(16)
     */
    async enAESGCM(key, data) {
        this._processed = 0;
        const k = toU8(key);
        const d = toU8(data);
        if (k.length !== 32) throw new Error("key size must be 32 bytes");
        const iv = Random(12);
        const aesKey = k;

        try {
            if (isNode) {
                const cipher = deps.crypto.createCipheriv('aes-256-gcm', aesKey, iv);
                const encrypted = Buffer.concat([cipher.update(d), cipher.final()]);
                const tag = cipher.getAuthTag();
                this._processed = d.length;
                return new Uint8Array(Buffer.concat([iv, encrypted, tag]));

            } else {
                const importedKey = await deps.crypto.subtle.importKey(
                    "raw", aesKey, "AES-GCM", false, ["encrypt"]
                );
                const res = await deps.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv }, importedKey, d
                ); // res = ciphertext + tag
                this._processed = d.length;
                const result = new Uint8Array(12 + res.byteLength);
                result.set(iv, 0);
                result.set(new Uint8Array(res), 12);
                return result;
            }

        } finally {
            zeroize(aesKey);
        }
    }

    /**
     * deAESGCM: Simple AES-GCM Decryption
     * @param {Uint8Array} key - 32 bytes
     * @param {Uint8Array} data - IV(12) + ciphertext + tag(16)
     * @returns {Promise<Uint8Array>} plaintext
     */
    async deAESGCM(key, data) {
        this._processed = 0;
        const k = toU8(key);
        const d = toU8(data);
        if (k.length !== 32) throw new Error("key size must be 32 bytes");
        if (d.length < 28) throw new Error("cipher too short");
        const iv = d.slice(0, 12);
        const aesKey = k;

        try {
            if (isNode) {
                const tag = d.slice(d.length - 16);
                const ciphertext = d.slice(12, d.length - 16);
                const decipher = deps.crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
                decipher.setAuthTag(tag);
                const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
                this._processed = d.length;
                return new Uint8Array(plaintext);

            } else {
                const importedKey = await deps.crypto.subtle.importKey(
                    "raw", aesKey, "AES-GCM", false, ["decrypt"]
                );
                try {
                    const res = await deps.crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: iv }, importedKey, d.slice(12)
                    ); // input is ciphertext + tag
                    this._processed = d.length;
                    return new Uint8Array(res);
                } catch (e) {
                    throw new Error("Decryption failed (MAC check failed)");
                }
            }

        } finally {
            zeroize(aesKey);
        }
    }

    /**
     * enAESGCMx: Stream/Chunked Encryption
     * @param {Uint8Array} key 
     * @param {Object} src - Must have `async read(size)` returning Uint8Array
     * @param {number} size - Total size of input
     * @param {Object} dst - Must have `async write(chunk)`
     * @param {number} chunkSize 
     */
    async enAESGCMx(key, src, size, dst, chunkSize = 1048576) {
        this._processed = 0;
        const k = toU8(key);
        if (k.length !== 32) throw new Error("key size must be 32 bytes");
        const globalIV = Random(12);
        const aesKeyBytes = k;
        let count = 0;

        // Pre-import key (Browser optimization)
        let webKey = null;
        if (!isNode) {
            webKey = await deps.crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["encrypt"]);
        }

        // Setup Pipeline
        let writeChain = Promise.resolve().then(() => dst.write(globalIV)); // Ensures sequential writes
        let nextChunkPromise = src.read(chunkSize > size ? size : chunkSize); // Start First Read
        let remaining = size;

        do {
            // A. Wait for Read (Current)
            const chunk = await nextChunkPromise;
            if (!chunk || (chunk.length === 0 && remaining > 0)) break;
            remaining -= chunk.length; // Update remaining

            // B. Trigger Next Read
            if (remaining > 0) {
                nextChunkPromise = src.read(Math.min(chunkSize, remaining));
            } else {
                nextChunkPromise = Promise.resolve(null);
            }

            // C. Prepare IV (Synchronous, order-sensitive)
            const iv = mkiv(globalIV, count);
            count++;

            // D. Encrypt (Async - runs parallel to Next Read)
            let encryptedDataPromise;
            if (isNode) {
                const cipher = deps.crypto.createCipheriv('aes-256-gcm', aesKeyBytes, iv);
                const enc = cipher.update(chunk);
                const final = cipher.final();
                const tag = cipher.getAuthTag();
                encryptedDataPromise = Promise.resolve(Buffer.concat([enc, final, tag])); // wrap in promise
            } else {
                encryptedDataPromise = deps.crypto.subtle.encrypt(
                    { name: "AES-GCM", iv: iv }, webKey, chunk
                ).then(buf => new Uint8Array(buf));
            }

            // E. Wait for Encryption to finish (CPU task)
            const encryptedData = await encryptedDataPromise;
            this._processed += chunk.length;

            // F. Schedule Write (Write-Behind)
            writeChain = writeChain.then(() => dst.write(encryptedData));
        } while (remaining > 0);

        // G. Finalize: Wait for all pending writes to finish
        await writeChain;
        zeroize(aesKeyBytes);
    }

    /**
     * deAESGCMx: Stream/Chunked Decryption
     * @param {Uint8Array} key 
     * @param {Object} src - Must have `async read(size)`
     * @param {number} size - Total size of ciphertext (including tags)
     * @param {Object} dst - Must have `async write(chunk)`
     * @param {number} chunkSize 
     */
    async deAESGCMx(key, src, size, dst, chunkSize = 1048576) {
        this._processed = 0;
        const k = toU8(key);
        if (k.length !== 32) throw new Error("key size must be 32 bytes");
        if (size < 28) throw new Error("cipher too short to decrypt");
        const globalIV = await src.read(12);
        const aesKeyBytes = k;
        let count = 0;
        this._processed = 12;

        // Pre-import key (Browser optimization)
        let webKey = null;
        if (!isNode) {
            webKey = await deps.crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["decrypt"]);
        }

        // helper to read block (chunk + tag), and return { chunk, tag }
        const readBlock = async (cSize) => {
            const c = await src.read(cSize);
            const t = await src.read(16); // Tag is always 16
            if (!t || t.length !== 16) throw new Error("Unexpected EOF reading tag");
            return { chunk: c, tag: t };
        };

        // Setup Pipeline
        let writeChain = Promise.resolve();
        let remaining = size - 12;
        let nextBlockPromise = readBlock(Math.min(chunkSize, remaining - 16)); // read first block

        do { // Must have at least tag bytes
            // A. Wait for Read
            const block = await nextBlockPromise;
            if (!block) break;
            remaining -= block.chunk.length + 16;

            // B. Trigger Next Read
            if (remaining > 16) {
                nextBlockPromise = readBlock(Math.min(chunkSize, remaining - 16));
            } else {
                nextBlockPromise = Promise.resolve(null);
            }

            // C. Prepare IV
            const iv = mkiv(globalIV, count);
            count++;

            // D. Decrypt
            let plaintextPromise;
            if (isNode) {
                const decipher = deps.crypto.createDecipheriv('aes-256-gcm', aesKeyBytes, iv);
                decipher.setAuthTag(block.tag);
                plaintextPromise = Promise.resolve(
                    Buffer.concat([decipher.update(block.chunk), decipher.final()])
                ); // wrap in promise
            } else {
                const combined = new Uint8Array(block.chunk.length + 16); // WebCrypto needs Combined buffer
                combined.set(block.chunk);
                combined.set(block.tag, block.chunk.length);
                plaintextPromise = deps.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv }, webKey, combined
                ).then(buf => new Uint8Array(buf));
            }

            // E. Wait for Decryption to finish (CPU task)
            const plaintext = await plaintextPromise;
            this._processed += block.chunk.length + 16;

            // E. Schedule Write
            writeChain = writeChain.then(() => dst.write(plaintext));
        } while (remaining > 16);

        // F. Finalize
        await writeChain;
        zeroize(aesKeyBytes);
    }
}

// ========== Asymetric Encryption Master ==========
export class AsymMaster {
    /**
     * @param {string} algo
     */
    constructor(algo) {
        if (algo === "ecc1") {
            this.algo = algo;
            this.worker = new ECC1();
        } else if (algo === "pqc1") {
            this.algo = algo;
            this.worker = new PQC1();
        } else {
            throw new Error(`Unsupported algorithm: ${algo}`);
        }
    }

    /**
     * Generate key pair
     * @returns {Promise<[Uint8Array, Uint8Array]>} [pub, pri]
     */
    async Genkey() {
        if (this.algo === "ecc1") {
            return await this.worker.genkey();
        } else if (this.algo === "pqc1") {
            return await this.worker.genkey();
        }
    }

    async Loadkey(publicBuf, privateBuf) {
        await this.worker.loadkey(publicBuf, privateBuf);
    }

    async Encrypt(data) {
        return await this.worker.encrypt(data);
    }

    async Decrypt(data) {
        return await this.worker.decrypt(data);
    }

    async Sign(data) {
        return await this.worker.sign(data);
    }

    async Verify(data, signature) {
        return await this.worker.verify(data, signature);
    }
}

// ========== ECC Encryption ==========
class ECC1 {
    constructor() {
        this.pubX = null; // 56 bytes
        this.priX = null; // 56 bytes
        this.pubEd = null; // 57 bytes
        this.priEd = null; // 57 bytes
    }

    /**
     * Generate Curve448 Key Pair: [X448 56B][Ed448 57B] format
     * @returns {Promise<[Uint8Array, Uint8Array]>} (public, private)
     */
    async genkey() {
        if (isNode) {
            // X448 - Raw export supported in Node 16+
            const xKp = deps.crypto.generateKeyPairSync('x448');
            const pubX = xKp.publicKey.export({ format: 'raw', type: 'spki' });
            const priX = xKp.privateKey.export({ format: 'raw', type: 'pkcs8' });

            // Ed448
            const edKp = deps.crypto.generateKeyPairSync('ed448');
            const pubEd = edKp.publicKey.export({ format: 'raw', type: 'spki' });
            const priEd = edKp.privateKey.export({ format: 'raw', type: 'pkcs8' });

            // Concat
            const pubFull = new Uint8Array(113);
            pubFull.set(new Uint8Array(pubX), 0);
            pubFull.set(new Uint8Array(pubEd), 56);
            const priFull = new Uint8Array(113);
            priFull.set(new Uint8Array(priX), 0);
            priFull.set(new Uint8Array(priEd), 56);

            // Assign
            this.pubX = new Uint8Array(pubX); this.priX = new Uint8Array(priX);
            this.pubEd = new Uint8Array(pubEd); this.priEd = new Uint8Array(priEd);
            return [pubFull, priFull];

        } else {
            // Generate keys
            const priX = deps.noble.x448.utils.randomPrivateKey();
            const pubX = deps.noble.x448.getPublicKey(priX);
            const priEd = deps.noble.ed448.utils.randomPrivateKey();
            const pubEd = deps.noble.ed448.getPublicKey(priEd);

            // Concat
            const pubFull = new Uint8Array(113);
            pubFull.set(pubX, 0);
            pubFull.set(pubEd, 56);
            const priFull = new Uint8Array(113);
            priFull.set(priX, 0);
            priFull.set(priEd, 56);

            // Assign
            this.pubX = pubX; this.priX = priX;
            this.pubEd = pubEd; this.priEd = priEd;
            return [pubFull, priFull];
        }
    }

    /**
     * Load Curve448 Key Pair: [X448 56B][Ed448 57B] format
     * @param {Uint8Array} pub 
     * @param {Uint8Array} pri 
     */
    async loadkey(pub, pri) {
        if (pub != null) {
            const p = toU8(pub);
            if (p.length !== 113) throw new Error("Invalid Curve448 public key length (must be 113 bytes)");
            this.pubX = p.slice(0, 56);
            this.pubEd = p.slice(56, 113);
        }
        if (pri != null) {
            const p = toU8(pri);
            if (p.length !== 113) throw new Error("Invalid Curve448 private key length (must be 113 bytes)");
            this.priX = p.slice(0, 56);
            this.priEd = p.slice(56, 113);
        }
    }

    /**
     * encrypt with public key
     * @param {Uint8Array} data
     * @param {Uint8Array} receiver
     * @returns {Promise<Uint8Array>}
     */
    async encrypt(data) {
        const d = toU8(data);
        let sharedSecret, ephPubRaw;
        if (isNode) {
            // make temp key
            const ephKp = deps.crypto.generateKeyPairSync('x448');
            ephPubRaw = ephKp.publicKey.export({ format: 'raw', type: 'spki' });

            // get shared secret
            const peerKeyObj = deps.crypto.createPublicKey({ key: this.pubX, format: 'raw', type: 'spki' });
            sharedSecret = deps.crypto.diffieHellman({
                privateKey: ephKp.privateKey,
                publicKey: peerKeyObj
            });
            ephPubRaw = new Uint8Array(ephPubRaw); // ensure Uint8Array
        } else {
            // make temp key, get shared secret
            const ephPri = deps.noble.x448.utils.randomPrivateKey();
            ephPubRaw = deps.noble.x448.getPublicKey(ephPri);
            sharedSecret = deps.noble.x448.getSharedSecret(ephPri, this.pubX);
        }

        // encrypt
        const gcmKey = genkey(new Uint8Array(sharedSecret), "KEYGEN_ECC1_ENCRYPT", 32);
        zeroize(sharedSecret);
        let em = new SymMaster("gcm1", gcmKey);
        const enc = await em.EnBin(d);
        zeroize(gcmKey);

        // Pack: [EphPub 56B][Enc]
        const res = new Uint8Array(ephPubRaw.length + enc.length);
        res.set(ephPubRaw, 0);
        res.set(enc, ephPubRaw.length);
        return res;
    }

    /**
     * decrypt with private key
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async decrypt(data) {
        // parse data
        const d = toU8(data);
        if (d.length < 56) throw new Error("cipher too short");
        const ephPubRaw = d.slice(0, 56);
        const enc = d.slice(56);

        // get shared secret
        let sharedSecret;
        if (isNode) {
            const ephKeyObj = deps.crypto.createPublicKey({ key: ephPubRaw, format: 'raw', type: 'spki' });
            const myPriKeyObj = deps.crypto.createPrivateKey({ key: this.priX, format: 'raw', type: 'x448' });
            sharedSecret = deps.crypto.diffieHellman({
                privateKey: myPriKeyObj,
                publicKey: ephKeyObj
            });
        } else {
            sharedSecret = deps.noble.x448.getSharedSecret(this.priX, ephPubRaw);
        }

        // decrypt
        const gcmKey = genkey(new Uint8Array(sharedSecret), "KEYGEN_ECC1_ENCRYPT", 32);
        zeroize(sharedSecret);
        let em = new SymMaster("gcm1", gcmKey);
        try {
            return await em.DeBin(enc);
        } finally {
            zeroize(gcmKey);
        }
    }

    /** 
     * sign with private key, Ed448
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async sign(data) {
        const d = toU8(data);
        if (isNode) {
            const myPriKeyObj = deps.crypto.createPrivateKey({ key: this.priEd, format: 'raw', type: 'ed448' });
            return new Uint8Array(deps.crypto.sign(null, d, myPriKeyObj));
        } else {
            return deps.noble.ed448.sign(d, this.priEd);
        }
    }

    /** 
     * verify with public key, Ed448
     * @param {Uint8Array} data
     * @param {Uint8Array} signature
     * @returns {Promise<boolean>}
     */
    async verify(data, signature) {
        const d = toU8(data);
        const s = toU8(signature);
        if (isNode) {
            const myPubKeyObj = deps.crypto.createPublicKey({ key: this.pubEd, format: 'raw', type: 'spki' });
            return deps.crypto.verify(null, d, myPubKeyObj, s);
        } else {
            return deps.noble.ed448.verify(s, d, this.pubEd);
        }
    }
}

// ========== PQC1 Encryption ==========
class PQC1 {
    constructor() {
        // ECC Key Objects
        this.pubX = null; // 56 bytes
        this.priX = null; // 56 bytes
        this.pubEd = null; // 57 bytes
        this.priEd = null; // 57 bytes

        // PQC Key Bytes
        this.pubKEM = null; // 1568 bytes
        this.priKEM = null; // 3168 bytes
        this.pubDSA = null; // 2592 bytes
        this.priDSA = null; // 4896 bytes

        this.mask = new Masker();
    }

    /**
     * Generate PQC1 Key Pair
     * @returns {Promise<[Uint8Array, Uint8Array]>} (public, private)
     */
    async genkey() {
        // 1. Curve448 key generation
        let pub0, pri0, pub1, pri1;
        if (isNode) {
            const xKp = deps.crypto.generateKeyPairSync('x448');
            pub0 = new Uint8Array(xKp.publicKey.export({ format: 'raw', type: 'spki' }));
            pri0 = new Uint8Array(xKp.privateKey.export({ format: 'raw', type: 'pkcs8' }));

            const edKp = deps.crypto.generateKeyPairSync('ed448');
            pub1 = new Uint8Array(edKp.publicKey.export({ format: 'raw', type: 'spki' }));
            pri1 = new Uint8Array(edKp.privateKey.export({ format: 'raw', type: 'pkcs8' }));

        } else {
            pri0 = deps.noble.x448.utils.randomPrivateKey();
            pub0 = deps.noble.x448.getPublicKey(pri0);
            pri1 = deps.noble.ed448.utils.randomPrivateKey();
            pub1 = deps.noble.ed448.getPublicKey(pri1);
        }

        this.priX = pri0; this.pubX = pub0;
        this.priEd = pri1; this.pubEd = pub1;

        // 2. ML-KEM-1024 & ML-DSA-87 key generation
        const kemKeys = deps.ml_kem1024.keygen();
        this.pubKEM = kemKeys.publicKey;
        this.priKEM = kemKeys.secretKey;

        const dsaKeys = deps.ml_dsa87.keygen();
        this.pubDSA = dsaKeys.publicKey;
        this.priDSA = dsaKeys.secretKey;

        // 3. join keys (Public: 4273B, Private: 8177B)
        const pubB = new Uint8Array(4273);
        pubB.set(pub0, 0);
        pubB.set(pub1, 56);
        pubB.set(this.pubKEM, 113);
        pubB.set(this.pubDSA, 1681);

        const priB = new Uint8Array(8177);
        priB.set(pri0, 0);
        priB.set(pri1, 56);
        priB.set(this.priKEM, 113);
        priB.set(this.priDSA, 3281);

        // mask PQC privtes
        this.priKEM = this.mask.XOR(this.priKEM);
        this.priDSA = this.mask.XOR(this.priDSA);
        return [pubB, priB];
    }

    /**
     * Load PQC1 Key Pair
     * @param {Uint8Array} publicBuf 
     * @param {Uint8Array} privateBuf 
     */
    async loadkey(publicBuf, privateBuf) {
        if (publicBuf) {
            const p = toU8(publicBuf);
            if (p.length !== 4273) throw new Error("Invalid PQC1 public key length");
            this.pubX = p.slice(0, 56);
            this.pubEd = p.slice(56, 113);
            this.pubKEM = p.slice(113, 1681);
            this.pubDSA = p.slice(1681, 4273);
        }
        if (privateBuf) {
            const p = toU8(privateBuf);
            if (p.length !== 8177) throw new Error("Invalid PQC1 private key length");
            this.priX = p.slice(0, 56);
            this.priEd = p.slice(56, 113);
            this.priKEM = this.mask.XOR(p.slice(113, 3281));
            this.priDSA = this.mask.XOR(p.slice(3281, 8177));
        }
    }

    /**
     * encrypt with public key
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async encrypt(data) {
        const d = toU8(data);

        // 1. Ephemeral X448 tempkey generation
        let ssvECC, tempPub;
        if (isNode) {
            const ephKp = deps.crypto.generateKeyPairSync('x448');
            tempPub = new Uint8Array(ephKp.publicKey.export({ format: 'raw', type: 'spki' }));
            const peerKeyObj = deps.crypto.createPublicKey({ key: this.pubX, format: 'raw', type: 'spki' });
            const sharedSecret = deps.crypto.diffieHellman({
                privateKey: ephKp.privateKey,
                publicKey: peerKeyObj
            });
            ssvECC = new Uint8Array(sharedSecret);
        } else {
            const tempPri = deps.noble.x448.utils.randomPrivateKey();
            tempPub = deps.noble.x448.getPublicKey(tempPri);
            ssvECC = deps.noble.x448.getSharedSecret(tempPri, this.pubX);
        }

        // 2. ML-KEM-1024 Encapsulation
        const { cipherText: kemEnc, sharedSecret: ssvKEM } = deps.ml_kem1024.encapsulate(this.pubKEM);

        // 3. Hybrid KDF & Encryption
        const combinedSecret = new Uint8Array(ssvECC.length + ssvKEM.length);
        combinedSecret.set(ssvECC, 0);
        combinedSecret.set(ssvKEM, ssvECC.length);
        zeroize(ssvECC);
        zeroize(ssvKEM);

        const gcmKey = genkey(combinedSecret, "KEYGEN_PQC1_ENCRYPT", 32);
        zeroize(combinedSecret);
        let em = new SymMaster("gcm1", gcmKey);
        const enc = await em.EnBin(d);
        zeroize(gcmKey);

        // [Temp X448 56B][Temp KEM 1568B][CipherText][Tag 16B]
        const res = new Uint8Array(56 + 1568 + enc.length);
        res.set(tempPub, 0);
        res.set(kemEnc, 56);
        res.set(enc, 1624);
        return res;
    }

    /**
     * decrypt with private key
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async decrypt(data) {
        const d = toU8(data);

        // 1. separate data
        const tempPub = d.slice(0, 56);
        const kemEnc = d.slice(56, 1624);
        const enc = d.slice(1624);

        // 2. Shared Secret Value
        let ssvECC;
        if (isNode) {
            const ephKeyObj = deps.crypto.createPublicKey({ key: tempPub, format: 'raw', type: 'spki' });
            const myPriKeyObj = deps.crypto.createPrivateKey({ key: this.priX, format: 'raw', type: 'x448' });
            const sharedSecret = deps.crypto.diffieHellman({
                privateKey: myPriKeyObj,
                publicKey: ephKeyObj
            });
            ssvECC = new Uint8Array(sharedSecret);
        } else {
            ssvECC = deps.noble.x448.getSharedSecret(this.priX, tempPub);
        }

        const priKEMt = this.mask.XOR(this.priKEM);
        const ssvKEM = deps.ml_kem1024.decapsulate(kemEnc, priKEMt);
        zeroize(priKEMt);

        // 3. Hybrid KDF & Decryption
        const combinedSecret = new Uint8Array(ssvECC.length + ssvKEM.length);
        combinedSecret.set(ssvECC, 0);
        combinedSecret.set(ssvKEM, ssvECC.length);
        zeroize(ssvECC);
        zeroize(ssvKEM);

        const gcmKey = genkey(combinedSecret, "KEYGEN_PQC1_ENCRYPT", 32);
        zeroize(combinedSecret);
        let em = new SymMaster("gcm1", gcmKey);
        try {
            return await em.DeBin(enc);
        } finally {
            zeroize(gcmKey);
        }
    }

    /** * sign with private key
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async sign(data) {
        const d = toU8(data);

        // ECC-Ed448 (114B)
        let edSgn;
        if (isNode) {
            const myPriKeyObj = deps.crypto.createPrivateKey({ key: this.priEd, format: 'raw', type: 'ed448' });
            edSgn = new Uint8Array(deps.crypto.sign(null, d, myPriKeyObj));
        } else {
            edSgn = deps.noble.ed448.sign(d, this.priEd);
        }

        // ML-DSA-87 (4627B)
        const priDSAt = this.mask.XOR(this.priDSA);
        const mlSgn = deps.ml_dsa87.sign(d, priDSAt);
        zeroize(priDSAt);

        // Join: 114 + 4627 = 4741
        const res = new Uint8Array(edSgn.length + mlSgn.length);
        res.set(edSgn, 0);
        res.set(mlSgn, edSgn.length);
        return res;
    }

    /** * verify with public key
     * @param {Uint8Array} data
     * @param {Uint8Array} signature
     * @returns {Promise<boolean>}
     */
    async verify(data, signature) {
        const d = toU8(data);
        const s = toU8(signature);

        if (s.length !== 4741) return false;
        const edSgn = s.slice(0, 114);
        const mlSgn = s.slice(114);

        let edValid = false;
        try {
            if (isNode) {
                const myPubKeyObj = deps.crypto.createPublicKey({ key: this.pubEd, format: 'raw', type: 'spki' });
                edValid = deps.crypto.verify(null, d, myPubKeyObj, edSgn);
            } else {
                edValid = deps.noble.ed448.verify(edSgn, d, this.pubEd);
            }
        } catch (e) {
            return false;
        }

        if (!edValid) return false;
        try {
            return deps.ml_dsa87.verify(mlSgn, d, this.pubDSA);
        } catch (e) {
            return false;
        }
    }
}