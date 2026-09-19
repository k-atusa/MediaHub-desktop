# test794a : USAG-Lib opsec
from typing import Dict, Union

import io
import zlib
import Bencrypt

def Crc32(data: bytes) -> str:
    return zlib.crc32(data).to_bytes(4, 'little').hex()

def PadLen(size: int) -> int:
    if size <= 0:
        return 0

    # 1. 0-16k: 4k*N
    if size <= 16384:
        remainder = size % 4096
        if remainder == 0:
            return 0
        return 4096 - remainder

    # get sup bit position
    bitLen = size.bit_length()
    if bitLen <= 24: # 16k-16m: K=2
        k = 2
    elif bitLen <= 29: # 16m-512m: K=3
        k = 3
    elif bitLen <= 33: # 512m-8g: K=4
        k = 4
    else: # 8g+: K=5
        k = 5

    # mask and ceiling
    shift = bitLen - k
    mask = (1 << shift) - 1
    if size & mask == 0: # on border size is not padded
        return 0

    # return actual padding length
    aftersize = ((size >> shift) + 1) << shift
    return aftersize - size

def PadFile(f: io.IOBase, size: int):
    for i in range(0, size // 1048576):
        f.write( Bencrypt.Random(1048576) )
    if size % 1048576 != 0:
        f.write( Bencrypt.Random(size % 1048576) )

def EncodeInt(data: int, size: int, signed: bool) -> bytes:
    return data.to_bytes(size, 'little', signed=signed)

def DecodeInt(data: bytes, signed: bool) -> int:
    return int.from_bytes(data, 'little', signed=signed)

def EncodeCfg(data: Dict[str, bytes]) -> bytes: # keysize max 127, datasize max 65535
    result = bytearray()
    for key, data in data.items():
        keyBytes = key.encode('utf-8')
        keyLen = len(keyBytes)
        dataLen = len(data)
        if keyLen > 127:
            raise ValueError(f"Key length too long: {keyLen}")
        if dataLen > 65535:
            raise ValueError(f"Data size too big: {dataLen}")
        if dataLen > 255: # dataLen > 255, datasize is 2B
            encodedKeyLen = keyLen + 128
            result.append(encodedKeyLen)
            result.extend(keyBytes)
            result.extend(dataLen.to_bytes(2, 'little'))
        else: # dataLen <= 255, datasize is 1B
            result.append(keyLen)
            result.extend(keyBytes)
            result.append(dataLen)
        result.extend(data)
    return bytes(result)

def DecodeCfg(data: bytes) -> Dict[str, bytes]: # format: [keyLen 1B][key][dataLen 1B/2B][data]
    result: Dict[str, bytes] = {}
    offset = 0
    totalLen = len(data)
    while offset < totalLen:
        keyLen = data[offset] # read keyLen
        isLongData = False
        offset += 1
        if keyLen > 127:
            keyLen -= 128
            isLongData = True
        keyBytes = data[offset : offset + keyLen] # read key
        key = keyBytes.decode('utf-8')
        offset += keyLen
        if isLongData: # dataLen is 2B
            dataLen = int.from_bytes(data[offset : offset + 2], 'little')
            offset += 2
        else: # dataLen is 1B
            dataLen = data[offset]
            offset += 1
        result[key] = data[offset : offset + dataLen] # read data
        offset += dataLen
    return result

# Opsec header handler
class Opsec:
    def __init__(self):
        self.Init()
        self.SaltLen = 32

    def __del__(self):
        self.Clear()
        if hasattr(self, 'BodyKey'):
            del self.BodyKey

    # set initial values
    def Init(self):
        self._headAlgo: str = ""
        self.Msg: str = "" # public message
        self.MsgInfo: bytes = b"" # additional info

        self._salt: bytes = b""
        self._encHeadData: bytes = b""

        self.Smsg: str = "" # private message
        self.SmsgInfo: bytes = b"" # private additional info (timestamp, ID, etc.)
        self._sign: bytes = b""

        self.BodyAlgo: str = "" # body encryption algorithm
        self.BodyKey: bytes = b"" # body encryption key
        self.BodySize: int = -1 # body size (-1 if not used)
        self.BodyInfo: bytes = b"" # additional info for body (packing info, etc.)

    # clear all (not practical, but to match with other codes)
    def Clear(self):
        self._salt = b""
        self._encHeadData = b""
        self.MsgInfo = b""
        self.SmsgInfo = b""
        self._sign = b""
        self.BodyKey = b""
        self.BodyInfo = b""
        self.Init()

    def Read(self, ins: io.IOBase, cut: int = 65535) -> bytes: # set cut to 0 to read all
        c = 0
        while True:
            data = ins.read(4)
            c += 4
            if data == b"":
                return b""
            elif data == b"YAS2":
                size = DecodeInt(ins.read(2), False)
                if size == 65535:
                    size += DecodeInt(ins.read(2), False)
                return ins.read(size)
            else:
                ins.read(124)
                c += 124
            if cut > 0 and c > cut:
                return b""

    def Write(self, outs: io.IOBase, head: bytes):
        outs.write(b"YAS2")
        size = len(head)
        if size < 65535:
            outs.write(EncodeInt(size, 2, False))
        elif size <= 65535 * 2:
            outs.write(EncodeInt(65535, 2, False))
            outs.write(EncodeInt(size - 65535, 2, False))
        else:
            raise ValueError(f"Header too big: {size}")
        outs.write(head)

    def _wrapEncHead(self) -> bytes:
        cfg: Dict[str, bytes] = {}
        if self.Smsg != "":
            cfg["smsg"] = self.Smsg.encode('utf-8')
        if self.SmsgInfo != b"":
            cfg["sinf"] = self.SmsgInfo
        if self._sign != b"":
            cfg["sgn"] = self._sign
        if self.BodyAlgo != "":
            cfg["bal"] = self.BodyAlgo.encode('utf-8')
        if self.BodyKey != b"":
            cfg["bkey"] = self.BodyKey
        if self.BodySize >= 0:
            if self.BodySize < 65536:
                cfg["bsz"] = EncodeInt(self.BodySize, 2, False)
            elif self.BodySize < 4294967296:
                cfg["bsz"] = EncodeInt(self.BodySize, 4, False)
            else:
                cfg["bsz"] = EncodeInt(self.BodySize, 8, False)
        if self.BodyInfo != b"":
            cfg["binf"] = self.BodyInfo
        return EncodeCfg(cfg)
    
    def _unwrapEncHead(self, data: bytes):
        cfg = DecodeCfg(data)
        if "smsg" in cfg:
            self.Smsg = cfg["smsg"].decode('utf-8')
        if "sinf" in cfg:
            self.SmsgInfo = cfg["sinf"]
        if "sgn" in cfg:
            self._sign = cfg["sgn"]
        if "bal" in cfg:
            self.BodyAlgo = cfg["bal"].decode('utf-8')
        if "bkey" in cfg:
            self.BodyKey = cfg["bkey"]
        if "bsz" in cfg:
            self.BodySize = DecodeInt(cfg["bsz"], False)
        if "binf" in cfg:
            self.BodyInfo = cfg["binf"]

    def Encpw(self, method: str, pw: bytes, kf: bytes = b"") -> bytes:
        # generate random parameters
        self._headAlgo = method
        self._salt = Bencrypt.Random(self.SaltLen)
        if self.BodySize >= 0:
            self.BodyKey = Bencrypt.Random(32)

        # get header key, encrypt header
        hm = Bencrypt.HashMaster(method)
        _, hkey = hm.KDF(pw + kf, self._salt)
        headData = self._wrapEncHead()
        sm = Bencrypt.SymMaster("gcm1", hkey)
        del hkey
        self._encHeadData = sm.EnBin(headData)
        del headData

        # warp header
        cfg: Dict[str, bytes] = {}
        if self.Msg != "":
            cfg["msg"] = self.Msg.encode('utf-8')
        if self.MsgInfo != b"":
            cfg["minf"] = self.MsgInfo
        cfg["hal"] = self._headAlgo.encode('utf-8')
        cfg["salt"] = self._salt
        cfg["ehd"] = self._encHeadData
        return EncodeCfg(cfg)
    
    def Encpub(self, method: str, peerPub: bytes, myPri: Union[bytes, None] = None) -> bytes: # sign if private is not None
        # generate random parameters
        self._headAlgo = method
        if self.BodySize >= 0:
            self.BodyKey = Bencrypt.Random(32)
        
        # sign with private key if provided
        if myPri != None:
            am = Bencrypt.AsymMaster(method)
            am.Loadkey(None, myPri)
            # sign to [hal][peerPub][smsg][sinf] with 0-byte suffix for each field
            signTgt = method.encode('utf-8') + b'\x00' + peerPub + b'\x00' + self.Smsg.encode('utf-8') + b'\x00' + self.SmsgInfo + b'\x00'
            self._sign = am.Sign(signTgt)

        # encrypt header
        am = Bencrypt.AsymMaster(method) # Bencrypt will check if method is valid
        am.Loadkey(peerPub, None)
        headData = self._wrapEncHead()
        self._encHeadData = am.Encrypt(headData)
        del headData

        # warp header
        cfg: Dict[str, bytes] = {}
        if self.Msg != "":
            cfg["msg"] = self.Msg.encode('utf-8')
        if self.MsgInfo != b"":
            cfg["minf"] = self.MsgInfo
        cfg["hal"] = self._headAlgo.encode('utf-8')
        cfg["ehd"] = self._encHeadData
        return EncodeCfg(cfg)
        
    def View(self, data: bytes):
        self.Init()
        cfg = DecodeCfg(data)
        if "msg" in cfg:
            self.Msg = cfg["msg"].decode('utf-8')
        if "minf" in cfg:
            self.MsgInfo = cfg["minf"]
        if "hal" in cfg:
            self._headAlgo = cfg["hal"].decode('utf-8')
        if "salt" in cfg:
            self._salt = cfg["salt"]
        if "ehd" in cfg:
            self._encHeadData = cfg["ehd"]

    def Decpw(self, pw: bytes, kf: bytes = b""):
        # check parameters, get header key
        if self._headAlgo == "":
            raise ValueError("Opsec not initialized or invalid data")
        hm = Bencrypt.HashMaster(self._headAlgo)
        _, hkey = hm.KDF(pw + kf, self._salt)

        # decrypt header (verification by SymMaster)
        sm = Bencrypt.SymMaster("gcm1", hkey)
        del hkey
        headData = sm.DeBin(self._encHeadData)
        self._unwrapEncHead(headData)
        del headData

    def Decpub(self, myPri: bytes, myPub: Union[bytes, None] = None, peerPub: Union[bytes, None] = None): # verify sign if public is not None
        # check parameters, decrypt header
        if self._headAlgo == "":
            raise ValueError("Opsec not initialized or invalid data")
        am = Bencrypt.AsymMaster(self._headAlgo)
        am.Loadkey(None, myPri)
        headData = am.Decrypt(self._encHeadData)
        self._unwrapEncHead(headData)
        del headData

        # verify sign
        if myPub == None and peerPub == None:
            return
        if myPub == None or peerPub == None:
            raise ValueError("Both myPub and peerPub should be provided to verify sign")
        am = Bencrypt.AsymMaster(self._headAlgo)
        am.Loadkey(peerPub, None)
        # verify sign [hal][myPub][smsg][sinf] with 0-byte suffix for each field
        signTgt = self._headAlgo.encode('utf-8') + b'\x00' + myPub + b'\x00' + self.Smsg.encode('utf-8') + b'\x00' + self.SmsgInfo + b'\x00'
        if not am.Verify(signTgt, self._sign):
            raise ValueError("Sign verification failed")