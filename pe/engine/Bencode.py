# test789a : USAG-Lib bencode

import base64
import unicodedata

splitable = ["!", "@", "#", "$", "%", "^", "&", "*", "~", "|"]

def Encode64(data: bytes, spliter: str = "", linenum: int = 40, colnum: int = 10) -> str:
    raw = "" if len(data) == 0 else base64.b64encode(data).decode('ascii')
    if spliter == "":
        return raw
    if spliter not in splitable:
        raise Exception("invalid spliter option")

    # split raw text
    lines = [ ]
    for i in range(0, len(raw), linenum):
        lines.append( raw[i:i+linenum] )
    cols = [ ]
    for i in range(0, len(lines), colnum):
        cols.append( lines[i:i+colnum] )

    # assemble text
    res = [f"{spliter}START{spliter}\n"]
    for i in range(0, len(cols)):
        res.append(f"{spliter}{i+1}/{len(cols)}{spliter}\n{'\n'.join(cols[i])}\n")
    res.append(f"{spliter}END{spliter}")
    return "".join(res)

def Decode64(data: str, spliter: str = "") -> bytes:
    data = data.replace("\t", "").replace("\r", "").replace("\n", "").replace(" ", "")
    if spliter != "" and (spliter not in splitable):
        raise Exception("invalid spliter option")

    # remove comments
    if spliter != "":
        temp, appendable, pos = [ ], True, 0
        while pos < len(data):
            if data[pos] == spliter:
                appendable = not appendable
            elif appendable:
                temp.append(data[pos])
            pos = pos + 1
        data = "".join(temp)

    if data == "":
        return b""
    return base64.b64decode(data)

def NormPW(pw: str) -> bytes:
    if pw == "":
        return b""
    return unicodedata.normalize('NFC', pw).encode('utf-8')