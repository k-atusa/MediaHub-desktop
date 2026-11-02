// test789b : USAG-Lib bencode
const isNode = (typeof window === 'undefined');

// ===== helpers =====
const splitable = new Set(["!", "@", "#", "$", "%", "^", "&", "*", "~", "|"]);

function _toBase64(uint8Array) {
    if (isNode) {
        return Buffer.from(uint8Array).toString('base64');
    } else {
        let binary = '';
        const len = uint8Array.byteLength;
        for (let i = 0; i < len; i++) binary += String.fromCharCode(uint8Array[i]);
        return btoa(binary);
    }
}

function _fromBase64(str) {
    if (isNode) {
        return new Uint8Array(Buffer.from(str, 'base64'));
    } else {
        const binary = atob(str);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }
}

// ===== main =====
export function Encode64(data, spliter = "", linenum = 40, colnum = 10) {
    // convert data to Uint8Array
    if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
    } else if (!(data instanceof Uint8Array)) {
        data = new Uint8Array(data || []);
    }

    // encode to base64
    let raw = "";
    if (data.length > 0) {
        raw = _toBase64(data);
    }

    // check spliter
    if (spliter === "") {
        return raw;
    }
    if (!splitable.has(spliter)) {
        throw new Error("invalid spliter option");
    }

    // split text
    const lines = [];
    for (let i = 0; i < raw.length; i += linenum) {
        lines.push(raw.slice(i, i + linenum));
    }
    const cols = [];
    for (let i = 0; i < lines.length; i += colnum) {
        cols.push(lines.slice(i, i + colnum));
    }

    // assemble text
    let res = `${spliter}START${spliter}\n`;
    const totalCols = cols.length;
    for (let i = 0; i < totalCols; i++) {
        res += `${spliter}${i + 1}/${totalCols}${spliter}\n${cols[i].join('\n')}\n`;
    }
    res += `${spliter}END${spliter}`;
    return res;
}

export function Decode64(data, spliter = "") {
    data = data.replace(/[\r\n \t]/g, "");
    if (spliter !== "" && !splitable.has(spliter)) {
        throw new Error("invalid spliter option");
    }

    // remove comment
    if (spliter !== "") {
        const parts = data.split(spliter);
        let pureData = "";
        for (let i = 0; i < parts.length; i += 2) {
            pureData += parts[i];
        }
        data = pureData;
    }

    // decode
    if (data === "") {
        return new Uint8Array(0);
    }
    return _fromBase64(data);
}

/**
 * @param {string} pw string
 * @returns {Uint8Array} NFC UTF-8 bytes
 */
export function NormPW(pw) {
    if (!pw) return new Uint8Array(0);
    const encoder = new TextEncoder();
    return encoder.encode(pw.normalize('NFC')); 
}