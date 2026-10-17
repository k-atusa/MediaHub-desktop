// test794b : USAG-Lib opsec
const BencryptURL = './Bencrypt.js';
const { Random, HashMaster, SymMaster, AsymMaster } = await import(BencryptURL);

// Helper: Fill zeros to buffer
function zeroize(arr) {
    if (arr && arr.byteLength > 0 && typeof arr.fill === 'function') {
        arr.fill(0);
        globalThis.DUMMY_CRYPTO_VOLATILE = arr;
    }
}

// Helper: Concatenate Uint8Arrays
function concat(arrays) {
    let totalLength = 0;
    for (const arr of arrays) {
        totalLength += arr.length;
    }
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// Helper: String to Uint8Array / Uint8Array to String
const enc = new TextEncoder();
const dec = new TextDecoder();
function strToU8(str) { return enc.encode(str); }
function u8ToStr(u8) { return dec.decode(u8); }

// Helper: CRC32 Implementation
const crcTable = (() => {
    let c;
    const table = [];
    for (let n = 0; n < 256; n++) {
        c = n;
        for (let k = 0; k < 8; k++) {
            c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
        }
        table[n] = c >>> 0;
    }
    return table;
})();


/**
 * CRC32 Implementation
 * @param {Uint8Array | string} data
 */
export function Crc32(data) {
    const u8 = typeof data === 'string' ? strToU8(data) : data;
    let crc = -1;
    for (let i = 0; i < u8.length; i++) {
        crc = (crc >>> 8) ^ crcTable[(crc ^ u8[i]) & 0xFF];
    }
    crc = (crc ^ (-1)) >>> 0;

    // Return as Hex String (8 chars)
    const buf = new ArrayBuffer(4);
    const view = new DataView(buf);
    view.setUint32(0, crc, true); // little endian
    let hexStr = "";
    for (let i = 0; i < 4; i++) {
        hexStr += view.getUint8(i).toString(16).padStart(2, '0');
    }
    return hexStr;
}

/**
 * Returns size to be padded
 * @param {number} size
 */
export function PadLen(size) {
    if (size <= 0) return 0;

    // 1. 0-16k: 4k*N
    if (size <= 16384) {
        const remainder = size % 4096;
        if (remainder === 0) return 0;
        return 4096 - remainder;
    }

    const bSize = BigInt(size);
    const bitLen = BigInt(bSize.toString(2).length); // get sup bit position
    let k;
    if (bitLen <= 24n) {        // 16k-16m: K=2
        k = 2n;
    } else if (bitLen <= 29n) { // 16m-512m: K=3
        k = 3n;
    } else if (bitLen <= 33n) { // 512m-8g: K=4
        k = 4n;
    } else {                    // 8g+: K=5
        k = 5n;
    }

    // mask and ceiling
    const shift = bitLen - k;
    const mask = (1n << shift) - 1n;
    if ((bSize & mask) === 0n) { // on border size is not padded
        return 0;
    }

    // return actual padding length
    const aftersize = ((bSize >> shift) + 1n) << shift;
    return Number(aftersize - bSize);
}

/**
 * Add padding at the end
 * @param {Object} f 
 * @param {number} size 
 */
export async function PadFile(f, size) {
    for (let i = 0; i < Math.floor(size / 32768); i++) await f.write(Random(32768));
    if (size % 32768 > 0) await f.write(Random(size % 32768));
}

/**
 * Little Endian Integer Encoding
 * @param {number} data 
 * @param {number} size 
 * @returns {Uint8Array}
 */
export function EncodeInt(data, size) {
    const buf = new ArrayBuffer(size);
    const view = new DataView(buf);
    if (size === 1) view.setUint8(0, data);
    else if (size === 2) view.setUint16(0, data, true);
    else if (size === 4) view.setUint32(0, data, true);
    else if (size === 8) view.setBigUint64(0, BigInt(data), true);
    return new Uint8Array(buf);
}

/**
 * Little Endian Integer Decoding
 * @param {Uint8Array} data 
 * @returns {number}
 */
export function DecodeInt(data) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (data.length === 1) return view.getUint8(0);
    if (data.length === 2) return view.getUint16(0, true);
    if (data.length === 4) return view.getUint32(0, true);
    if (data.length === 8) return Number(view.getBigUint64(0, true)); // Check logic if > safe integer
    return 0;
}

/**
 * Config Encoder, keysize max 127, datasize max 65535
 * @param {Object} data 
 * @returns {Uint8Array}
 */
export function EncodeCfg(data) {
    const chunks = [];
    for (const [key, val] of Object.entries(data)) {
        const valU8 = (typeof val === 'string') ? strToU8(val) : val;
        const keyBytes = strToU8(key);
        const keyLen = keyBytes.length;
        const dataLen = valU8.length;
        if (keyLen > 127) throw new Error(`Key length too long: ${keyLen}`);
        if (dataLen > 65535) throw new Error(`Data size too big: ${dataLen}`);

        if (dataLen > 255) { // DataLen > 255, datasize is 2B, keyLen Flag set (keyLen + 128)
            chunks.push(new Uint8Array([keyLen + 128]));
            chunks.push(keyBytes);
            chunks.push(EncodeInt(dataLen, 2));
        } else { // DataLen <= 255, datasize is 1B
            chunks.push(new Uint8Array([keyLen]));
            chunks.push(keyBytes);
            chunks.push(new Uint8Array([dataLen]));
        }
        chunks.push(valU8);
    }
    return concat(chunks);
}

/**
 * Config Decoder
 * @param {Uint8Array} data 
 * @returns {Object}
 */
export function DecodeCfg(data) {
    const result = {};
    let offset = 0;
    const totalLen = data.length;
    while (offset < totalLen) {
        // get key
        let keyLen = data[offset];
        let isLongData = false;
        offset += 1;
        if (keyLen > 127) {
            keyLen -= 128;
            isLongData = true;
        }
        const keyBytes = data.slice(offset, offset + keyLen);
        const key = u8ToStr(keyBytes);
        offset += keyLen;

        // get data
        let dataLen = 0;
        if (isLongData) {
            const lenBytes = data.slice(offset, offset + 2);
            dataLen = DecodeInt(lenBytes);
            offset += 2;
        } else {
            dataLen = data[offset];
            offset += 1;
        }
        result[key] = data.slice(offset, offset + dataLen);
        offset += dataLen;
    }
    return result;
}

// Opsec header handler
export class Opsec {
    constructor() {
        this.Init();
        this.SaltLen = 32
    }

    Clear() {
        zeroize(this._salt);
        zeroize(this._encHeadData);
        zeroize(this.MsgInfo);
        zeroize(this.SmsgInfo);
        zeroize(this._sign);
        zeroize(this.BodyKey);
        zeroize(this.BodyInfo);
        this.Init();
    }

    // set initial values
    Init() {
        this._headAlgo = "";
        this.Msg = "";
        this.MsgInfo = new Uint8Array(0);

        this._salt = new Uint8Array(0);
        this._encHeadData = new Uint8Array(0);

        this.Smsg = "";
        this.SmsgInfo = new Uint8Array(0);
        this._sign = new Uint8Array(0);

        this.BodyAlgo = "";
        this.BodyKey = new Uint8Array(0);
        this.BodySize = -1;
        this.BodyInfo = new Uint8Array(0);
    }

    /**
     * read stream, returns Opsec header
     * @param {Object} ins // Object with async read(size)
     * @param {number} cut 
     * @returns {Uint8Array}
     */
    async Read(ins, cut = 65535) {
        let c = 0;
        while (true) {
            const data = await ins.read(4);
            c += 4;
            if (data.length === 0) return new Uint8Array(0);

            const magic = u8ToStr(data);
            if (magic === "YAS2") {
                const sizeBuf = await ins.read(2);
                let size = DecodeInt(sizeBuf);
                if (size === 65535) {
                    const extSizeBuf = await ins.read(2);
                    size += DecodeInt(extSizeBuf);
                }
                return await ins.read(size);
            } else {
                await ins.read(124);
                c += 124;
            }
            if (cut > 0 && c > cut) return new Uint8Array(0);
        }
    }

    /**
     * write opsec header to stream
     * @param {Object} outs // Object with async write(data)
     * @param {Uint8Array} head
     */
    async Write(outs, head) {
        await outs.write(strToU8("YAS2"));
        const size = head.length;
        if (size < 65535) {
            await outs.write(EncodeInt(size, 2));
        } else if (size <= 65535 * 2) {
            await outs.write(EncodeInt(65535, 2));
            await outs.write(EncodeInt(size - 65535, 2));
        } else {
            throw new Error(`Header too big: ${size}`);
        }
        await outs.write(head);
    }

    _wrapEncHead() {
        const cfg = {};
        if (this.Smsg !== "") cfg["smsg"] = this.Smsg;
        if (this.SmsgInfo.length > 0) cfg["sinf"] = this.SmsgInfo;
        if (this._sign.length > 0) cfg["sgn"] = this._sign;
        if (this.BodyAlgo !== "") cfg["bal"] = this.BodyAlgo;
        if (this.BodyKey.length > 0) cfg["bkey"] = this.BodyKey;
        if (this.BodySize >= 0) {
            if (this.BodySize < 65536) cfg["bsz"] = EncodeInt(this.BodySize, 2);
            else if (this.BodySize < 4294967296) cfg["bsz"] = EncodeInt(this.BodySize, 4);
            else cfg["bsz"] = EncodeInt(this.BodySize, 8);
        }
        if (this.BodyInfo.length > 0) cfg["binf"] = this.BodyInfo;
        return EncodeCfg(cfg);
    }

    _unwrapEncHead(data) {
        const cfg = DecodeCfg(data);
        if (cfg["smsg"]) this.Smsg = u8ToStr(cfg["smsg"]);
        if (cfg["sinf"]) this.SmsgInfo = cfg["sinf"];
        if (cfg["sgn"]) this._sign = cfg["sgn"];
        if (cfg["bal"]) this.BodyAlgo = u8ToStr(cfg["bal"]);
        if (cfg["bkey"]) this.BodyKey = cfg["bkey"];
        if (cfg["bsz"]) this.BodySize = DecodeInt(cfg["bsz"]);
        if (cfg["binf"]) this.BodyInfo = cfg["binf"];
    }

    /**
     * Encrypt with password, returns header
     * @param {string} method 
     * @param {Uint8Array} pw 
     * @param {Uint8Array} kf 
     * @returns {Uint8Array}
     */
    async Encpw(method, pw, kf = new Uint8Array(0)) {
        // generate random parameters
        this._headAlgo = method;
        this._salt = Random(this.SaltLen);
        if (this.BodySize >= 0) {
            this.BodyKey = Random(32);
        }

        const pwBytes = (typeof pw === 'string') ? strToU8(pw) : pw;
        const kfBytes = (typeof kf === 'string') ? strToU8(kf) : kf;
        const combinedPw = concat([pwBytes, kfBytes]);

        // get header key, encrypt header
        const hm = new HashMaster(method);
        const [, hkey] = await hm.KDF(combinedPw, this._salt);
        zeroize(combinedPw);

        const headData = this._wrapEncHead();
        const sm = new SymMaster("gcm1", hkey);
        this._encHeadData = await sm.EnBin(headData);
        zeroize(headData);
        zeroize(hkey);

        // wrap header
        const cfg = {};
        if (this.Msg !== "") cfg["msg"] = this.Msg;
        if (this.MsgInfo.length > 0) cfg["minf"] = this.MsgInfo;
        cfg["hal"] = this._headAlgo;
        cfg["salt"] = this._salt;
        cfg["ehd"] = this._encHeadData;
        return EncodeCfg(cfg);
    }

    /**
     * Encrypt with public key, returns header
     * @param {string} method 
     * @param {Uint8Array} peerPub 
     * @param {Uint8Array|null} myPri 
     * @returns {Uint8Array}
     */
    async Encpub(method, peerPub, myPri = null) {
        // generate random parameters
        this._headAlgo = method;
        if (this.BodySize >= 0) {
            this.BodyKey = Random(32);
        }

        const peerPubBytes = (typeof peerPub === 'string') ? strToU8(peerPub) : peerPub;

        // sign with private key if provided
        if (myPri !== null) {
            const am = new AsymMaster(method);
            await am.Loadkey(null, myPri);
            // sign to [hal][peerPub][smsg][sinf] with 0-byte suffix for each field
            const signTgt = concat([
                strToU8(method),
                new Uint8Array([0]),
                peerPubBytes,
                new Uint8Array([0]),
                strToU8(this.Smsg),
                new Uint8Array([0]),
                this.SmsgInfo,
                new Uint8Array([0])
            ]);
            this._sign = await am.Sign(signTgt);
            zeroize(signTgt);
        }

        // encrypt header
        const am = new AsymMaster(method);
        await am.Loadkey(peerPubBytes, null);
        const headData = this._wrapEncHead();
        this._encHeadData = await am.Encrypt(headData);
        zeroize(headData);

        // wrap header
        const cfg = {};
        if (this.Msg !== "") cfg["msg"] = this.Msg;
        if (this.MsgInfo.length > 0) cfg["minf"] = this.MsgInfo;
        cfg["hal"] = this._headAlgo;
        cfg["ehd"] = this._encHeadData;
        return EncodeCfg(cfg);
    }

    /**
     * load outer layer of header
     * @param {Uint8Array} data
     */
    View(data) {
        this.Init();
        const cfg = DecodeCfg(data);
        if (cfg["msg"]) this.Msg = u8ToStr(cfg["msg"]);
        if (cfg["minf"]) this.MsgInfo = cfg["minf"];
        if (cfg["hal"]) this._headAlgo = u8ToStr(cfg["hal"]);
        if (cfg["salt"]) this._salt = cfg["salt"];
        if (cfg["ehd"]) this._encHeadData = cfg["ehd"];
    }

    /**
     * Decrypt with password
     * @param {Uint8Array} pw 
     * @param {Uint8Array} kf 
     */
    async Decpw(pw, kf = new Uint8Array(0)) {
        if (this._headAlgo === "") throw new Error("Opsec not initialized or invalid data");
        const pwBytes = (typeof pw === 'string') ? strToU8(pw) : pw;
        const kfBytes = (typeof kf === 'string') ? strToU8(kf) : kf;
        const combinedPw = concat([pwBytes, kfBytes]);

        // check parameters, get header key
        const hm = new HashMaster(this._headAlgo);
        const [, hkey] = await hm.KDF(combinedPw, this._salt);
        zeroize(combinedPw);

        // decrypt header (verification by SymMaster)
        const sm = new SymMaster("gcm1", hkey);
        const headData = await sm.DeBin(this._encHeadData);
        zeroize(hkey);
        this._unwrapEncHead(headData);
        zeroize(headData);
    }

    /**
     * Decrypt with private key
     * @param {Uint8Array} myPri 
     * @param {Uint8Array|null} myPub 
     * @param {Uint8Array|null} peerPub
     */
    async Decpub(myPri, myPub = null, peerPub = null) {
        // check parameters, decrypt header
        if (this._headAlgo === "") throw new Error("Opsec not initialized or invalid data");
        const am = new AsymMaster(this._headAlgo);
        await am.Loadkey(null, myPri);

        let headData = await am.Decrypt(this._encHeadData);
        this._unwrapEncHead(headData);
        zeroize(headData);

        // verify sign
        if (myPub === null && peerPub === null) return;
        if (myPub === null || peerPub === null) {
            if (this._sign.length > 0) throw new Error("Both myPub and peerPub should be provided to verify sign");
            return;
        }

        const amVerify = new AsymMaster(this._headAlgo);
        await amVerify.Loadkey(peerPub, null);
        // verify sign [hal][myPub][smsg][sinf] with 0-byte suffix for each field
        const signTgt = concat([
            strToU8(this._headAlgo),
            new Uint8Array([0]),
            myPub,
            new Uint8Array([0]),
            strToU8(this.Smsg),
            new Uint8Array([0]),
            this.SmsgInfo,
            new Uint8Array([0])
        ]);

        const verified = await amVerify.Verify(signTgt, this._sign);
        if (!verified) throw new Error("Sign verification failed");
    }
}
