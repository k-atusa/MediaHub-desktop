import http.server
import socketserver
import threading
import requests
import re
import urllib.parse
from Cryptodome.Cipher import AES

import Bencrypt
import Opsec


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Range")
        self.end_headers()

    def do_GET(self):
        path = urllib.parse.unquote(self.path)
        m = re.match(r"^/stream/([^/]+)/(.*)$", path)
        if not m:
            self.send_error(404, "Not Found")
            return
        fPid, fName = m.group(1), m.group(2)
        srv = self.server

        with srv.lock:
            if fName not in srv.flMap:
                self.send_error(404, "File Not Found")
                return
            flInfo = srv.flMap[fName]
            cli = srv.cli

        fk = flInfo[:44]
        aesKey = fk[:32]
        origSz = Opsec.DecodeInt(flInfo[44:52], False)
        fpid = cli.objPid(fk)

        PL = 1048576
        CL = PL + 16

        # parse Range header
        rS, rE = 0, origSz - 1
        partial = False
        rng = self.headers.get("Range")
        if rng:
            rm = re.match(r"bytes=(\d+)-(\d*)", rng)
            if rm:
                rS = int(rm.group(1))
                if rm.group(2):
                    rE = int(rm.group(2))
                partial = True
            else:
                rm2 = re.match(r"bytes=-(\d+)", rng)
                if rm2:
                    rS = max(0, origSz - int(rm2.group(1)))
                    partial = True

        if rS > rE or rS >= origSz:
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{origSz}")
            self.end_headers()
            return

        fi, li = rS // PL, rE // PL
        cLen = rE - rS + 1

        ext = fName.split('.')[-1].lower()
        mime = {
            "mp4": "video/mp4", "webm": "video/webm", "mov": "video/mp4",
            "mkv": "video/x-matroska", "png": "image/png", "jpg": "image/jpeg",
            "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
            "svg": "image/svg+xml", "pdf": "application/pdf"
        }.get(ext, "application/octet-stream")

        if partial:
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {rS}-{rE}/{origSz}")
        else:
            self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(cLen))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        gIV = srv.getIV(cli, fPid, fpid)
        if not gIV:
            return

        for ci in range(fi, li + 1):
            chunk = srv.getChunk(cli, fPid, fpid, aesKey, origSz, ci, gIV)
            if not chunk:
                break
            base = ci * PL
            a = max(rS, base) - base
            b = min(rE, base + len(chunk) - 1) - base
            if a <= b:
                try:
                    self.wfile.write(chunk[a:b + 1])
                except Exception:
                    break


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.cli = None
        self.flMap = {}
        self.lock = threading.Lock()
        self._ivC = {}
        self._chkC = {}

    def getIV(self, cli, fPid, fpid):
        ck = f"{fPid}_{fpid}"
        with self.lock:
            if ck in self._ivC:
                return self._ivC[ck]
        res = requests.get(f"{cli.url}/api/media/{fPid}/{fpid}/dat",
                           headers={"Range": "bytes=0-11"}, verify=cli.verify_ssl)
        if res.status_code in [200, 206] and len(res.content) == 12:
            with self.lock:
                self._ivC[ck] = res.content
            return res.content
        return None

    def getChunk(self, cli, fPid, fpid, aesKey, origSz, idx, gIV):
        ck = f"{fPid}_{fpid}_{idx}"
        with self.lock:
            if ck in self._chkC:
                return self._chkC[ck]
        PL = 1048576
        CL = PL + 16
        cS = 12 + idx * CL
        pLen = min(PL, origSz - idx * PL)
        cLen = pLen + 16
        cE = cS + cLen - 1
        res = requests.get(f"{cli.url}/api/media/{fPid}/{fpid}/dat",
                           headers={"Range": f"bytes={cS}-{cE}"}, verify=cli.verify_ssl)
        if res.status_code not in [200, 206] or len(res.content) != cLen:
            return None
        buf = res.content
        iv = Bencrypt.mkiv(gIV, idx)
        cipher = AES.new(aesKey, AES.MODE_GCM, nonce=iv)
        try:
            plain = cipher.decrypt_and_verify(buf[:-16], buf[-16:])
        except ValueError:
            return None
        with self.lock:
            self._chkC[ck] = plain
            if len(self._chkC) > 16:
                del self._chkC[next(iter(self._chkC))]
        return plain


class MHProxy:
    def __init__(self, port=18080):
        self.port = port
        self.srv = _Server(("127.0.0.1", port), _Handler)
        self.thd = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def start(self):
        self.thd.start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thd.join(timeout=2)

    def updCtx(self, cli, flMap):
        with self.srv.lock:
            self.srv.cli = cli
            self.srv.flMap = flMap
            self.srv._ivC.clear()
            self.srv._chkC.clear()
