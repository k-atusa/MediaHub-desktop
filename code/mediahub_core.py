import os
import time
import tempfile
import requests
import urllib3
import cv2

import Bencode
import Bencrypt
import Opsec

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        if name in self.fldMap:
            raise Exception("Folder name already exists!")
        self.fldMap[name] = Bencrypt.Random(32) + Bencrypt.Random(12)
        sm = Bencrypt.SymMaster("gcm1", self.uKey[:32])
        enc = sm.EnBin(Opsec.EncodeCfg(self.fldMap))
        res = requests.post(f"{self.url}/api/userdata/{self.uHash}", data=enc, verify=self.verify_ssl)
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
        if not os.path.isfile(path):
            raise Exception("File not found")
        name = os.path.basename(path)
        origSz = os.path.getsize(path)

        # generate file key and derive ID
        fk = Bencrypt.Random(32) + Bencrypt.Random(12)
        fpid = self.objPid(fk)

        # thumbnail
        ext = name.split('.')[-1].lower()
        thumb = None
        if ext in ['mp4', 'webm', 'mov', 'mkv']:
            thumb = self.vidThumb(path)
        elif ext in ['jpg', 'jpeg', 'png', 'gif', 'webp']:
            thumb = self.imgThumb(path)
        if thumb:
            sm = Bencrypt.SymMaster("gcm1", fk[:32])
            requests.post(f"{self.url}/api/media/{fPid}/{fpid}/thumb",
                          data=sm.EnBin(thumb),
                          headers={'X-User-Hash': self.uHash}, verify=self.verify_ssl)

        # encrypt and upload media
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

            class _Wrap:
                def __init__(s, f, tot, cb):
                    s._f, s._tot, s._sent = f, tot, 0
                    s._cb, s._t0, s._wb = cb, time.monotonic(), 0
                def read(s, sz=-1):
                    c = s._f.read(sz)
                    if c:
                        s._sent += len(c); s._wb += len(c)
                        now = time.monotonic(); el = now - s._t0
                        if el >= 0.5 and s._cb:
                            s._cb(s._sent, s._tot, s._wb / el)
                            s._t0 = now; s._wb = 0
                    return c
                def __len__(s):
                    return s._tot

            res = requests.post(
                f"{self.url}/api/media/{fPid}/{fpid}/dat",
                data=_Wrap(tmp, total, progCb),
                headers={'Content-Length': str(total), 'X-User-Hash': self.uHash},
                verify=self.verify_ssl)
            if res.status_code != 200:
                raise Exception(f"Upload failed: code {res.status_code}")
            if progCb:
                progCb(total, total, 0)

        # update metadata
        flMap[name] = fk + Opsec.EncodeInt(origSz, 8, False)
        sm = Bencrypt.SymMaster("gcm1", fKey[:32])
        res = requests.post(
            f"{self.url}/api/storage/{fPid}/names",
            data=sm.EnBin(Opsec.EncodeCfg(flMap)),
            headers={'X-User-Hash': self.uHash}, verify=self.verify_ssl)
        if res.status_code != 200:
            raise Exception(f"Failed to sync metadata: code {res.status_code}")
        return True

    def dnFile(self, fPid, flInfo, name, outDir):
        fk = flInfo[:44]
        origSz = Opsec.DecodeInt(flInfo[44:52], False)
        fpid = self.objPid(fk)
        smx = Bencrypt.SymMaster("gcmx1", fk[:32])
        ciphSz = smx.AfterSize(origSz)
        res = requests.get(f"{self.url}/api/media/{fPid}/{fpid}/dat",
                           stream=True, verify=self.verify_ssl)
        if res.status_code in [200, 206]:
            out = os.path.join(outDir, name)
            with open(out, "wb") as f:
                smx.DeFile(res.raw, ciphSz, f)
            return out
        else:
            raise Exception(f"Download failed: {res.status_code}")
