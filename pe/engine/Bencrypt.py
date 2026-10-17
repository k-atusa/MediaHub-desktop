# test793a : USAG-Lib bencrypt
from typing import Optional, Tuple

import threading
import io
import secrets
import hashlib
import hmac

from argon2 import low_level

from Cryptodome.Cipher import AES

from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization

from pqcrypto.kem.ml_kem_1024 import generate_keypair as mlkem_gen, encrypt as mlkem_enc, decrypt as mlkem_dec
from pqcrypto.sign.ml_dsa_87 import generate_keypair as mldsa_gen, sign as mldsa_sign, verify as mldsa_verify

# ========== Basic Functions ==========
def Random(size: int) -> bytes:
    return secrets.token_bytes(size)

def SHA3256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def HMAC3256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha3_256).digest()

def SHA3512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def HMAC3512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha3_512).digest()

def genkey(data: bytes, lbl: str, size: int) -> bytes: # HMAC-SHA3-512
    key = hmac.new(data, lbl.encode('utf-8'), hashlib.sha3_512).digest()
    if size > len(key):
        raise ValueError("key size too large")
    return key[:size]

def mkiv(g: bytes, c: int) -> bytearray:
    g, c = bytearray(g), c.to_bytes(8, 'little')
    for i in range(0, 8):
        g[4 + i] ^= c[i]
    return g

# ========== Data Masker ==========
class Masker:
    _instance = None # singleton
    _PRIME_CANDIDATES = [
        15485863, 32452843, 86028121, 104395301,
        179424673, 228017633, 236887691, 345098717,
        413158511, 481230491, 563117203, 693240851,
        715225741, 812349821, 882046271, 999999937
    ]

    def __new__(cls, pool_size_mb: int = 8):
        if cls._instance is None:
            cls._instance = super(Masker, cls).__new__(cls)
            cls._instance._initialize(pool_size_mb)
        return cls._instance
    
    def __del__(self):
        if hasattr(self, 'pool') and isinstance(self.pool, bytearray):
            for i in range(len(self.pool)):
                self.pool[i] = 0
            del self.pool

    def _initialize(self, pool_size_mb: int):
        self.POOL_SIZE = pool_size_mb * 1024 * 1024
        self.pool = bytearray(Random(self.POOL_SIZE))
        self.prime = self._PRIME_CANDIDATES[secrets.randbelow(len(self._PRIME_CANDIDATES))]

    def XOR(self, data: bytes) -> bytes:
        L = len(data)
        if L == 0:
            return b''
        elif L == 1:
            return bytes([data[0] ^ self.pool[self.prime % self.POOL_SIZE]])
        elif L > self.POOL_SIZE:
            raise ValueError(f"Data {L} exceeds Pool {self.POOL_SIZE}")
        mid = L // 2
        left, right = data[:mid], data[mid:]

        # 5-Round Feistel Network
        for _ in range(5):
            seed = 0
            for i, b in enumerate(right):
                seed = (seed + b * (i + 1)) % self.POOL_SIZE
            new_left = bytes(a ^ self.pool[(seed + i * self.prime) % self.POOL_SIZE] for i, a in enumerate(left))
            left, right = right, new_left
        return right + left # re-order for odd length

# ========== Hash Function Master ==========
class HashMaster:
    def __init__(self, algo: str, hashSize: int = 32, keySize: int = 32):
        if algo not in ["sha3", "arg2low", "arg2st"]:
            raise ValueError(f"Unsupported algorithm: {algo}")
        self.algo = algo
        self.hashSize = hashSize
        self.keySize = keySize
    
    def KDF(self, pw: bytes, salt: bytes) -> Tuple[bytes, bytes]: # (PW storage, user key)
        lblStore, lblKeygen, master = "", "", None
        if self.algo == "sha3":
            lblStore, lblKeygen = "PWHASH_SHA3", "KEYGEN_SHA3"
            master = SHA3512(salt + pw)
        elif self.algo == "arg2low":
            lblStore, lblKeygen = "PWHASH_ARG2LOW", "KEYGEN_ARG2LOW"
            master = argon2low(pw, salt)
        elif self.algo == "arg2st":
            lblStore, lblKeygen = "PWHASH_ARG2ST", "KEYGEN_ARG2ST"
            master = argon2st(pw, salt)
        else:
            return (None, None)
        pwStore, keyGen = genkey(master, lblStore, self.hashSize), genkey(master, lblKeygen, self.keySize)
        del master
        return pwStore, keyGen
    
# ========== Hash Functions ==========
def argon2low(pw: bytes, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(secret=pw, salt=salt, time_cost=4, memory_cost=65536, parallelism=8, hash_len=64, type=low_level.Type.ID)

def argon2st(pw: bytes, salt: bytes) -> bytes:
    return low_level.hash_secret_raw(secret=pw, salt=salt, time_cost=3, memory_cost=262144, parallelism=6, hash_len=64, type=low_level.Type.ID)

# ========== Symmetric Encryption Master ==========
class SymMaster:
    def __init__(self, algo: str, key: bytes):
        if algo not in ["gcm1", "gcmx1"]:
            raise ValueError(f"Unsupported algorithm: {algo}")
        self.algo = algo
        if self.algo == 'gcm1' or self.algo == 'gcmx1':
            if len(key) != 32:
                raise ValueError(f"SYM keysize must be 32: got {len(key)}")
            self.mask = Masker()
            self.key, self.worker = self.mask.XOR(key), AES1() # saved as XOR masked

    def __del__(self):
        if hasattr(self, 'mask'):
            del self.mask
        if hasattr(self, 'key'):
            del self.key

    def AfterSize(self, size: int) -> int:
        if self.algo == "gcm1":
            return size + 28
        elif self.algo == "gcmx1":
            c = size // 1048576 + 1
            if size != 0 and size % 1048576 == 0:
                c -= 1
            return size + 12 + 16 * c
        
    def Processed(self) -> int:
        if self.algo == 'gcm1' or self.algo == 'gcmx1':
            return self.worker.processed()

    def EnBin(self, data: bytes) -> bytes:
        if self.algo == "gcm1":
            return self.worker.enAESGCM(self.mask.XOR(self.key), data)
        elif self.algo == "gcmx1":
            wr = io.BytesIO()
            self.worker.enAESGCMx(self.mask.XOR(self.key), io.BytesIO(data), len(data), wr)
            return wr.getvalue()

    def DeBin(self, data: bytes) -> bytes:
        if self.algo == "gcm1":
            return self.worker.deAESGCM(self.mask.XOR(self.key), data)
        elif self.algo == "gcmx1":
            wr = io.BytesIO()
            self.worker.deAESGCMx(self.mask.XOR(self.key), io.BytesIO(data), len(data), wr)
            return wr.getvalue()

    def EnFile(self, src: io.IOBase, size: int, dst: io.IOBase):
        if self.algo == "gcm1":
            data = self.worker.enAESGCM(self.mask.XOR(self.key), src.read(size))
            dst.write(data)
        elif self.algo == "gcmx1":
            self.worker.enAESGCMx(self.mask.XOR(self.key), src, size, dst)

    def DeFile(self, src: io.IOBase, size: int, dst: io.IOBase):
        if self.algo == "gcm1":
            data = self.worker.deAESGCM(self.mask.XOR(self.key), src.read(size))
            dst.write(data)
        elif self.algo == "gcmx1":
            self.worker.deAESGCMx(self.mask.XOR(self.key), src, size, dst)

# ========== AES Encryption ==========
class AES1:
    def __init__(self):
        self._processed: int = 0
        self._lock = threading.Lock()

    def processed(self) -> int:
        with self._lock:
            return self._processed

    def enAESGCM(self, key: bytes, data: bytes) -> bytes: # AES-GCM
        with self._lock: self._processed = 0
        if len(key) != 32:
            raise ValueError("key size must be 32 bytes")
        iv = Random(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with self._lock: self._processed = len(data)
        return iv + ciphertext + tag # [IV 12B][encdata][tag 16B]

    def deAESGCM(self, key: bytes, data: bytes) -> bytes: # AES-GCM
        with self._lock: self._processed = 0
        if len(key) != 32:
            raise ValueError("key size must be 32 bytes")
        if len(data) < 28:
            raise ValueError("cipher too short")
        iv = data[:12]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(data[12:-16], data[-16:])
        with self._lock: self._processed = len(data)
        return plaintext

    def enAESGCMx(self, key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int = 1048576): # AES-GCM extended
        with self._lock: self._processed = 0
        if len(key) != 32:
            raise ValueError("key size must be 32 bytes")
        globalIV, globalKey, count = Random(12), key, 0
        dst.write(globalIV)
        for i in range(0, size // chunkSize):
            iv = mkiv(globalIV, count)
            count += 1
            cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
            chunk = src.read(chunkSize)
            ciphertext, tag = cipher.encrypt_and_digest(chunk)
            dst.write(ciphertext)
            dst.write(tag)
            with self._lock: self._processed += chunkSize
        if size == 0 or size % chunkSize != 0:
            iv = mkiv(globalIV, count)
            cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
            chunk = src.read(size % chunkSize)
            ciphertext, tag = cipher.encrypt_and_digest(chunk)
            dst.write(ciphertext)
            dst.write(tag)
            with self._lock: self._processed += size % chunkSize

    def deAESGCMx(self, key: bytes, src: io.IOBase, size: int, dst: io.IOBase, chunkSize: int = 1048576): # AES-GCM extended
        with self._lock: self._processed = 0
        if len(key) != 32:
            raise ValueError("key size must be 32 bytes")
        if size < 28:
            raise ValueError("cipher too short to decrypt")
        globalIV = src.read(12)
        globalKey, count = key, 0
        rem_size = size - 12
        with self._lock: self._processed = 12
        for i in range(0, rem_size // (chunkSize + 16)):
            iv = mkiv(globalIV, count)
            count += 1
            cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
            chunk = src.read(chunkSize)
            tag = src.read(16)
            plaintext = cipher.decrypt_and_verify(chunk, tag)
            dst.write(plaintext)
            with self._lock: self._processed += chunkSize + 16
        if rem_size == 0 or rem_size % (chunkSize + 16) != 0:
            iv = mkiv(globalIV, count)
            cipher = AES.new(globalKey, AES.MODE_GCM, nonce=iv)
            chunk = src.read(rem_size % (chunkSize + 16) - 16)
            tag = src.read(16)
            plaintext = cipher.decrypt_and_verify(chunk, tag)
            dst.write(plaintext)
            with self._lock: self._processed += rem_size % (chunkSize + 16)

# ========== Asymmetric Encryption Master ==========
class AsymMaster:
    def __init__(self, algo: str):
        if algo not in ["ecc1", "pqc1"]:
            raise ValueError(f"Unsupported algorithm: {algo}")
        self.algo = algo
        if self.algo == 'ecc1':
            self.worker = ECC1()
        elif self.algo == 'pqc1':
            self.worker = PQC1()

    def __del__(self):
        if hasattr(self, 'worker'):
            del self.worker

    def Genkey(self) -> Tuple[bytes, bytes]:
        if self.algo == 'ecc1':
            return self.worker.genkey()
        elif self.algo == 'pqc1':
            return self.worker.genkey()

    def Loadkey(self, public: bytes|None, private: bytes|None):
        if self.algo in ["ecc1", "pqc1"]:
            self.worker.loadkey(public, private)

    def Encrypt(self, data: bytes) -> bytes:
        if self.algo in ["ecc1", "pqc1"]:
            return self.worker.encrypt(data)

    def Decrypt(self, data: bytes) -> bytes:
        if self.algo in ["ecc1", "pqc1"]:
            return self.worker.decrypt(data)

    def Sign(self, data: bytes) -> bytes:
        if self.algo in ["ecc1", "pqc1"]:
            return self.worker.sign(data)

    def Verify(self, data: bytes, signature: bytes) -> bool:
        if self.algo in ["ecc1", "pqc1"]:
            return self.worker.verify(data, signature)


# ========== ECC Encryption ==========
class ECC1: # Curve448
    def __init__(self):
        self.pubX: Optional[x448.X448PublicKey] = None
        self.priX: Optional[x448.X448PrivateKey] = None
        self.pubEd: Optional[ed448.Ed448PublicKey] = None
        self.priEd: Optional[ed448.Ed448PrivateKey] = None

    def __del__(self):
        self.pubX = None
        self.priX = None
        self.pubEd = None
        self.priEd = None

    def genkey(self) -> Tuple[bytes, bytes]: # [X448 56B][Ed448 57B] format, (public, private)
        # 1. Generate both keys
        self.priX = x448.X448PrivateKey.generate()
        self.pubX = self.priX.public_key()
        self.priEd = ed448.Ed448PrivateKey.generate()
        self.pubEd = self.priEd.public_key()

        # 2. Get Raw Bytes
        pub0 = self.pubX.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pri0 = self.priX.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub1 = self.pubEd.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pri1 = self.priEd.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

        # 3. Join to 113B
        return (pub0 + pub1, pri0 + pri1)

    def loadkey(self, public: bytes|None, private: bytes|None): # [X448 56B][Ed448 57B] format, load if not None
        if public != None:
            if len(public) != 113: raise ValueError(f"ECC1 keysize must be 113: got {len(public)}")
            self.pubX = x448.X448PublicKey.from_public_bytes(public[:56])
            self.pubEd = ed448.Ed448PublicKey.from_public_bytes(public[56:])
        if private != None:
            if len(private) != 113: raise ValueError(f"ECC1 keysize must be 113: got {len(private)}")
            self.priX = x448.X448PrivateKey.from_private_bytes(private[:56])
            self.priEd = ed448.Ed448PrivateKey.from_private_bytes(private[56:])

    def encrypt(self, data: bytes) -> bytes: # encrypt with public key
        tempKey = x448.X448PrivateKey.generate() # 1. Generate temp ephemeral key
        tempPub = tempKey.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = tempKey.exchange(self.pubX) # 2. Get shared secret (ECDH)
        gcmKey = genkey(shared, "KEYGEN_ECC1_ENCRYPT", 32)
        enc = SymMaster("gcm1", gcmKey).EnBin(data) # 3. Encrypt with AES-GCM

        del tempKey
        del shared
        del gcmKey
        return tempPub + enc

    def decrypt(self, data: bytes) -> bytes:
        # 1. parse data
        if len(data) < 56:
            raise ValueError("cipher too short")
        tempPub = data[:56]
        enc = data[56:]

        # 2. Load key, Get shared secret (ECDH)
        tempKey = x448.X448PublicKey.from_public_bytes(tempPub)
        shared = self.priX.exchange(tempKey)

        # 3. Decrypt with AES-GCM
        gcmKey = genkey(shared, "KEYGEN_ECC1_ENCRYPT", 32)
        del tempKey
        del shared
        return SymMaster("gcm1", gcmKey).DeBin(enc)

    def sign(self, data: bytes) -> bytes: # Ed448
        return self.priEd.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool: # Ed448
        try:
            self.pubEd.verify(signature, data)
            return True
        except:
            return False

# ========== PQC1 Encryption ==========
class PQC1:
    def __init__(self):
        # ECC Key Objects
        self.pubX: Optional[x448.X448PublicKey] = None
        self.priX: Optional[x448.X448PrivateKey] = None
        self.pubEd: Optional[ed448.Ed448PublicKey] = None
        self.priEd: Optional[ed448.Ed448PrivateKey] = None
        
        # PQC Key Bytes
        self.pubKEM: Optional[bytes] = None
        self.priKEM: Optional[bytes] = None
        self.pubDSA: Optional[bytes] = None
        self.priDSA: Optional[bytes] = None

        # save PQC bytes as XOR masked
        self.mask = Masker()

    def __del__(self):
        self.pubX = None
        self.priX = None
        self.pubEd = None
        self.priEd = None

        self.pubKEM = None
        self.priKEM = None
        self.pubDSA = None
        self.priDSA = None

        self.mask = None

    def genkey(self) -> Tuple[bytes, bytes]: # (public, private)
        # 1. Curve448 key generation
        self.priX = x448.X448PrivateKey.generate()
        self.pubX = self.priX.public_key()
        self.priEd = ed448.Ed448PrivateKey.generate()
        self.pubEd = self.priEd.public_key()

        # get raw bytes
        pub0 = self.pubX.public_bytes_raw() # 56B
        pri0 = self.priX.private_bytes_raw() # 56B
        pub1 = self.pubEd.public_bytes_raw() # 57B
        pri1 = self.priEd.private_bytes_raw() # 57B

        # 2. ML-KEM-1024 & ML-DSA-87 key generation
        self.pubKEM, self.priKEM = mlkem_gen()
        self.pubDSA, self.priDSA = mldsa_gen()

        # 3. join keys (Public: 4273B, Private: 8177B)
        pubB = pub0 + pub1 + self.pubKEM + self.pubDSA
        priB = pri0 + pri1 + self.priKEM + self.priDSA
        self.priKEM, self.priDSA = self.mask.XOR(self.priKEM), self.mask.XOR(self.priDSA) # save as XOR masked
        return (pubB, priB)

    def loadkey(self, public: bytes|None, private: bytes|None):
        if public:
            if len(public) != 4273: raise ValueError("Invalid PQC1 public key length")
            self.pubX = x448.X448PublicKey.from_public_bytes(public[:56])
            self.pubEd = ed448.Ed448PublicKey.from_public_bytes(public[56:113])
            self.pubKEM = public[113:1681]  # 113 + 1568
            self.pubDSA = public[1681:4273] # 1681 + 2592
            
        if private:
            if len(private) != 8177: raise ValueError("Invalid PQC1 private key length")
            self.priX = x448.X448PrivateKey.from_private_bytes(private[:56])
            self.priEd = ed448.Ed448PrivateKey.from_private_bytes(private[56:113])
            self.priKEM = self.mask.XOR(private[113:3281])  # 113 + 3168
            self.priDSA = self.mask.XOR(private[3281:8177]) # 3281 + 4896

    def encrypt(self, data: bytes) -> bytes:
        # 1. Ephemeral X448 tempkey generation
        tempKey = x448.X448PrivateKey.generate()
        tempPub = tempKey.public_key().public_bytes_raw()
        ssvECC = tempKey.exchange(self.pubX) # 56B

        # 2. ML-KEM-1024 Encapsulation
        kemEnc, ssvKEM = mlkem_enc(self.pubKEM) # Cipher 1568B, Secret 32B

        # 3. Hybrid KDF & Encryption
        gcmKey = genkey(ssvECC + ssvKEM, "KEYGEN_PQC1_ENCRYPT", 32)
        enc = SymMaster("gcm1", gcmKey).EnBin(data)

        # [Temp X448 56B][Temp KEM 1568B][CipherText][Tag 16B]
        del tempKey
        del ssvECC
        del ssvKEM
        del gcmKey
        return tempPub + kemEnc + enc

    def decrypt(self, data: bytes) -> bytes:
        # 1. seperate data
        if len(data) < 1624:
            raise ValueError("cipher too short")
        tempPub = data[:56]
        kemEnc = data[56:1624]
        enc = data[1624:]

        # 2. Shared Secret Value
        tempXKey = x448.X448PublicKey.from_public_bytes(tempPub)
        ssvECC = self.priX.exchange(tempXKey)
        ssvKEM = mlkem_dec(self.mask.XOR(self.priKEM), kemEnc)

        # 3. Hybrid KDF & Decryption
        gcmKey = genkey(ssvECC + ssvKEM, "KEYGEN_PQC1_ENCRYPT", 32)
        del tempXKey
        del ssvECC
        del ssvKEM
        return SymMaster("gcm1", gcmKey).DeBin(enc)

    def sign(self, data: bytes) -> bytes:
        # ECC-Ed448 (114B) + ML-DSA-87 (4627B)
        edSgn = self.priEd.sign(data)
        mlSgn = mldsa_sign(self.mask.XOR(self.priDSA), data)
        return edSgn + mlSgn

    def verify(self, data: bytes, signature: bytes) -> bool:
        if len(signature) != 4741: return False
        edSgn = signature[:114]
        mlSgn = signature[114:]
        try:
            self.pubEd.verify(edSgn, data)
            return mldsa_verify(self.pubDSA, data, mlSgn)
        except:
            return False