import os
import io
import time
import tempfile
import requests
import urllib3
import cv2

from engine import Bencode, Bencrypt, Opsec

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHUNK_SIZE = 2 * 1024 * 1024  # 2MB


class ChunkedRangeReader(io.RawIOBase):
    """Streams data from server in 2MB chunks via HTTP Range requests."""
    def __init__(self, url, total_size, chunk_size=CHUNK_SIZE, verify_ssl=True, headers=None, prog_cb=None):
        super().__init__()
        self.url = url
        self.total_size = total_size
        self.chunk_size = chunk_size
        self.verify_ssl = verify_ssl
        self.headers = dict(headers or {})
        self.prog_cb = prog_cb
        self.offset = 0
        self.buffer = bytearray()
        self.t0 = time.monotonic()
        self.wb = 0
        self.session = requests.Session()

    def readable(self):
        return True

    def readinto(self, b):
        needed = len(b)
        while len(self.buffer) < needed and self.offset < self.total_size:
            fetch_size = min(self.chunk_size, self.total_size - self.offset)
            fetch_end = self.offset + fetch_size - 1
            req_headers = dict(self.headers)
            req_headers['Range'] = f"bytes={self.offset}-{fetch_end}"
            res = self.session.get(self.url, headers=req_headers, verify=self.verify_ssl)
            if res.status_code not in [200, 206]:
                raise Exception(f"Download failed: code {res.status_code}")
            data = res.content
            if len(data) != fetch_size:
                raise Exception(f"Download chunk size mismatch: expected {fetch_size}, got {len(data)}")
            self.buffer.extend(data)
            self.offset += len(data)
            self.wb += len(data)
            now = time.monotonic()
            el = now - self.t0
            if el >= 0.5 and self.prog_cb:
                self.prog_cb(self.offset, self.total_size, self.wb / el)
                self.t0 = now
                self.wb = 0

        take = min(needed, len(self.buffer))
        b[:take] = self.buffer[:take]
        del self.buffer[:take]
        return take

    def read(self, size=-1):
        if size is None or size < 0:
            size = self.total_size - (self.offset - len(self.buffer))
        while len(self.buffer) < size and self.offset < self.total_size:
            fetch_size = min(self.chunk_size, self.total_size - self.offset)
            fetch_end = self.offset + fetch_size - 1
            req_headers = dict(self.headers)
            req_headers['Range'] = f"bytes={self.offset}-{fetch_end}"
            res = self.session.get(self.url, headers=req_headers, verify=self.verify_ssl)
            if res.status_code not in [200, 206]:
                raise Exception(f"Download failed: code {res.status_code}")
            data = res.content
            if len(data) != fetch_size:
                raise Exception(f"Download chunk size mismatch: expected {fetch_size}, got {len(data)}")
            self.buffer.extend(data)
            self.offset += len(data)
            self.wb += len(data)
            now = time.monotonic()
            el = now - self.t0
            if el >= 0.5 and self.prog_cb:
                self.prog_cb(self.offset, self.total_size, self.wb / el)
                self.t0 = now
                self.wb = 0

        take = min(size, len(self.buffer))
        out = bytes(self.buffer[:take])
        del self.buffer[:take]
        return out

    def close(self):
        self.session.close()
        super().close()


class MHClient:
    def __init__(self, url, user, pw, verify_ssl=True):
        self.url = url.rstrip('/')
        self.user = user
        self.pw = pw
        self.verify_ssl = verify_ssl
        self.uHash = None
        self.uKey = None
        self.fldMap = {}

    def usrPid(self, key):
        return Bencrypt.SHA3256(key)[:16].hex()

    def objPid(self, key):
        return key[32:44].hex()

    def auth(self):
        PEPPER = "_PROJECT_WHY_MEDIAHUB_PEPPER_2026_!@#$"
        salt = Bencrypt.SHA3256((self.user + PEPPER).encode('utf-8'))
        pw = Bencode.NormPW(self.pw)
        hm = Bencrypt.HashMaster("arg2st")
        stKey, uKey = hm.KDF(pw, salt)
        self.uHash = self.usrPid(stKey)
        self.uKey = uKey

    def setAuth(self, uHash, uKey):
        self.uHash = uHash
        self.uKey = uKey

    def getFlds(self):
        if not self.uHash:
            raise Exception("Not authenticated")
        res = requests.get(f"{self.url}/api/userdata/{self.uHash}", verify=self.verify_ssl)
        if res.status_code == 200:
            if len(res.content) > 0:
                sm = Bencrypt.SymMaster("gcm1", self.uKey[:32])
                self.fldMap = Opsec.DecodeCfg(sm.DeBin(res.content))
            else:
                self.fldMap = {}
        else:
            raise Exception(f"Connection Error: code {res.status_code}")
        return self.fldMap

    def mkFld(self, name):
        if not self.uHash:
            raise Exception("Not authenticated")
        if name in self.fldMap:
            raise Exception("Folder name already exists!")
        self.fldMap[name] = Bencrypt.Random(32) + Bencrypt.Random(12)
        sm = Bencrypt.SymMaster("gcm1", self.uKey[:32])
        enc = sm.EnBin(Opsec.EncodeCfg(self.fldMap))
        res = requests.post(f"{self.url}/api/userdata/{self.uHash}",
                            data=enc,
                            headers={'X-User-Hash': self.uHash},
                            verify=self.verify_ssl)
        if res.status_code != 200:
            raise Exception(f"Failed to create folder: code {res.status_code}")

    def getFiles(self, name):
        if name not in self.fldMap:
            raise Exception("Folder not found")
        fKey = self.fldMap[name]
        fPid = self.objPid(fKey)
        res = requests.get(f"{self.url}/api/storage/{fPid}/names", verify=self.verify_ssl)
        flMap = {}
        if res.status_code == 200 and len(res.content) > 0:
            sm = Bencrypt.SymMaster("gcm1", fKey[:32])
            flMap = Opsec.DecodeCfg(sm.DeBin(res.content))
        return fPid, fKey, flMap

    def _mkThumb(self, img):
        """Resize image frame to 256px thumbnail."""
        h, w = img.shape[:2]
        r = w / h
        if 0.6666 <= r <= 1.5:
            nw, nh = (256, int(256 / r)) if w >= h else (int(256 * r), 256)
            out = cv2.resize(img, (nw, nh))
        else:
            s = min(w, h)
            x, y = (w - s) // 2, (h - s) // 2
            out = cv2.resize(img[y:y+s, x:x+s], (256, 256))
        ok, enc = cv2.imencode('.jpg', out, [cv2.IMWRITE_JPEG_QUALITY, 70])
        return enc.tobytes() if ok else None

    def imgThumb(self, path):
        import numpy as np
        data = np.fromfile(path, dtype=np.uint8)
        img = cv2.imdecode(data, cv2.IMREAD_COLOR)
        return self._mkThumb(img) if img is not None else None

    def vidThumb(self, path):
        cap = cv2.VideoCapture(path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        cap.set(cv2.CAP_PROP_POS_FRAMES, int(fps) if fps > 0 else 1)
        ret, frame = cap.read()
        cap.release()
        return self._mkThumb(frame) if ret else None

    def upFile(self, fPid, fKey, flMap, path, progCb=None):
        if not self.uHash:
            raise Exception("Not authenticated")
        if not os.path.isfile(path):
            raise Exception("File not found")
        name = os.path.basename(path)
        origSz = os.path.getsize(path)

        # generate file key and derive ID
        fk = Bencrypt.Random(32) + Bencrypt.Random(12)
        fpid = self.objPid(fk)

        # thumbnail (POST: needs user authentication)
        ext = name.split('.')[-1].lower()
        thumb = None
        if ext in ['mp4', 'webm', 'mov', 'mkv']:
            thumb = self.vidThumb(path)
        elif ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
            thumb = self.imgThumb(path)
        if thumb:
            sm = Bencrypt.SymMaster("gcm1", fk[:32])
            res_thumb = requests.post(
                f"{self.url}/api/media/{fPid}/{fpid}/thumb",
                data=sm.EnBin(thumb),
                headers={'X-User-Hash': self.uHash},
                verify=self.verify_ssl)
            if res_thumb.status_code != 200:
                raise Exception(f"Thumbnail upload failed: code {res_thumb.status_code}")

        # encrypt and upload media (POST in 2MB chunks with user authentication)
        smx = Bencrypt.SymMaster("gcmx1", fk[:32])
        encSz = smx.AfterSize(origSz)
        padSz = Opsec.PadLen(encSz)
        total = encSz + padSz

        with tempfile.TemporaryFile() as tmp:
            with open(path, "rb") as f:
                smx.EnFile(f, origSz, tmp)
            if padSz > 0:
                Opsec.PadFile(tmp, padSz)
            tmp.seek(0)

            offset = 0
            t0 = time.monotonic()
            wb = 0

            if total == 0:
                res = requests.post(
                    f"{self.url}/api/media/{fPid}/{fpid}/dat",
                    data=b"",
                    headers={
                        'Content-Length': '0',
                        'X-Upload-Offset': '0',
                        'X-User-Hash': self.uHash
                    },
                    verify=self.verify_ssl)
                if res.status_code != 200:
                    raise Exception(f"Upload failed: code {res.status_code}")
            else:
                while offset < total:
                    chunk = tmp.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    c_len = len(chunk)
                    res = requests.post(
                        f"{self.url}/api/media/{fPid}/{fpid}/dat",
                        data=chunk,
                        headers={
                            'Content-Length': str(c_len),
                            'X-Upload-Offset': str(offset),
                            'X-User-Hash': self.uHash
                        },
                        verify=self.verify_ssl)
                    if res.status_code != 200:
                        raise Exception(f"Upload failed: code {res.status_code}")
                    offset += c_len
                    wb += c_len
                    now = time.monotonic()
                    el = now - t0
                    if el >= 0.5 and progCb:
                        progCb(offset, total, wb / el)
                        t0 = now
                        wb = 0

            if progCb:
                progCb(total, total, 0)

        # update metadata (POST: needs user authentication)
        flMap[name] = fk + Opsec.EncodeInt(origSz, 8, False)
        sm = Bencrypt.SymMaster("gcm1", fKey[:32])
        res = requests.post(
            f"{self.url}/api/storage/{fPid}/names",
            data=sm.EnBin(Opsec.EncodeCfg(flMap)),
            headers={'X-User-Hash': self.uHash},
            verify=self.verify_ssl)
        if res.status_code != 200:
            raise Exception(f"Failed to sync metadata: code {res.status_code}")
        return True

    def dnFile(self, fPid, flInfo, name, outDir, progCb=None):
        # GET request: no user authentication required by server
        fk = flInfo[:44]
        origSz = Opsec.DecodeInt(flInfo[44:52], False)
        fpid = self.objPid(fk)
        smx = Bencrypt.SymMaster("gcmx1", fk[:32])
        ciphSz = smx.AfterSize(origSz)

        url = f"{self.url}/api/media/{fPid}/{fpid}/dat"
        reader = ChunkedRangeReader(
            url=url,
            total_size=ciphSz,
            chunk_size=CHUNK_SIZE,
            verify_ssl=self.verify_ssl,
            prog_cb=progCb
        )

        out = os.path.join(outDir, name)
        try:
            with open(out, "wb") as f:
                smx.DeFile(reader, ciphSz, f)
            if progCb:
                progCb(ciphSz, ciphSz, 0)
            return out
        except Exception:
            if os.path.exists(out):
                try:
                    os.remove(out)
                except Exception:
                    pass
            raise
        finally:
            reader.close()
