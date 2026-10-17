# MediaHub Desktop — Go/Wails 개발 계획서

> **목표**: 기존 MediaHub 웹 서비스의 데스크톱 클라이언트 버전.
> 분할 업다운로드 + 로컬 파일 기반 처리로 메모리 초과 없는 E2EE 클라이언트.
> **Go가 모든 암복호화와 세션 메모리를 담당 — JS 암호화 엔진 완전 제거.**

---

## 1. 현황 분석

### 1.1 기존 서버 API (`ge/sample/web_server.go`)

| API | 메서드 | 기능 |
|-----|--------|------|
| `/api/userdata/{hash}` | GET/POST/DELETE | 유저 암호화 폴더 맵 저장 |
| `/api/storage/{folderID}/names` | GET/POST/DELETE | 폴더 파일 맵 저장 |
| `/api/media/{fID}/{pID}/{dat\|thumb}` | GET/POST/DELETE | 암호화 미디어 파일 |
| `/api/notice` | GET | 공지 |
| `/api/trim/{folderID}` | POST | 고아 파일 삭제 |

- **업로드**: `X-Upload-Offset` 헤더로 청크 오프셋 기반 이어쓰기 지원
- **인증**: `X-User-Hash` 헤더 (파일 존재 여부 확인)

### 1.2 암호화 스택 (USAG-Lib, Go 전용)

| 계층 | 라이브러리 | 역할 |
|------|-----------|------|
| 대칭 암호화 | `Bencrypt.SymMaster` | AES-GCM / AES-GCMx1 (1MiB 청크) |
| 키 파생 | `Bencrypt.HashMaster` | SHA3 / Argon2id (arg2st) |
| 헤더 포맷 | `Opsec.Opsec` | `YAS2` 매직 + 암호화 헤더 |
| 메모리 보안 | `Bencrypt.Masker` | XOR 5-round Feistel 메모리 마스킹 |
| 키 포맷 | 44바이트 | [0:32]=AES키, [32:44]=GCM IV seed |

### 1.3 프론트엔드 구조 (`ge/public/`) — 유지 vs 제거

```
js/
  app.js            — 변경 없음
  core/
    adapter.js      ← 교체 (Wails 브릿지 얇은 래퍼, 암호화 코드 없음)
    drive.js        ← 교체 (UI 상태만, 키/암호화 로직 없음)
    router.js       — 변경 없음
    utils.js        — 변경 없음 (FormatBytes 등 UI 유틸만)
  views/
    drive.js        — 변경 없음 (UI 렌더링)
    login.js        — 변경 없음 (로그인 UI)
    viewer.js       — 변경 없음 (뷰어 UI)
  engine/
    Bencrypt.js     ← 제거 (Go가 담당)
    Opsec.js        ← 제거 (Go가 담당)
    Bencode.js      ← 제거 (Go가 담당)
    viewerjs.min.js — 유지 (미디어 뷰어, 암호화 무관)
```

> **핵심 방침**:
> - **`engine/` JS 암호화 라이브러리 전체 제거** — Go가 모든 암복호화와 세션 메모리를 담당
> - **`sw.js` 제거** — Service Worker 스트리밍을 Go localhost HTTP 서버로 대체
> - `adapter.js`는 Wails 브릿지 호출만 하는 얇은 래퍼 (키/Uint8Array 없음)
> - `drive.js`는 폴더명/파일명/크기 등 표시용 UI 상태만 관리

---

## 2. 데스크톱 클라이언트 설계

### 2.1 전체 아키텍처

```
┌──────────────────────────────────────────────────────┐
│                 Wails App Window                     │
│  ┌────────────────────────────────────────────────┐  │
│  │           WebView (프론트엔드)                 │  │
│  │  HTML/CSS: 그대로 재사용                       │  │
│  │  views/*.js: UI 렌더링 (그대로 재사용)          │  │
│  │  engine/viewerjs: 미디어 뷰어 (그대로 재사용)  │  │
│  │  core/adapter.js: Wails 브릿지 래퍼 (교체)     │  │
│  │  core/drive.js:   UI 상태 관리만 (교체)        │  │
│  │  ❌ engine/Bencrypt.js / Opsec.js / Bencode.js  │  │
│  │  ❌ sw.js (Service Worker 완전 제거)            │  │
│  └──────────────────────┬─────────────────────────┘  │
│     ↑ 이름/크기 등 표시 메타만 전달 (키 노출 없음)   │
│  ┌──────────────────────▼─────────────────────────┐  │
│  │              Go Backend (Wails)                │  │
│  │  session.go — 인메모리 세션 (Masker XOR 키)    │  │
│  │  crypto.go  — USAG-Lib 래핑 (키파생/암복호화)  │  │
│  │  transfer.go — 분할 업/다운로드 스트리밍 엔진  │  │
│  │  stream.go  — 로컬 미디어 스트리밍 HTTP 서버   │  │
│  │  app.go     — AppService: JS 브릿지 메서드     │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
         ↕ HTTPS
┌─────────────────────┐
│  MediaHub 서버       │
│  (기존 web_server.go)│
└─────────────────────┘
```

### 2.2 메모리 초과 문제 해결 전략

| 작업 | 웹 버전 문제 | 데스크톱 해결 방식 |
|------|------------|-------------------|
| **업로드** | JS 메모리에서 전체 암호화 + XHR | Go `EnFile` 스트리밍, 16MiB `X-Upload-Offset` 청크 |
| **다운로드** | JS 메모리에 전체 암호문 조립 | Go 임시파일 경유, `DeFile` 스트리밍 복호화 |
| **미디어 재생** | Service Worker + JS 복호화 | Go localhost HTTP 서버 실시간 복호화 + Range 응답 |

---

## 3. 파일 구조

```
ge/
├── wails.json               — Wails 프로젝트 설정
├── go.mod / go.sum          — Go 모듈
├── main.go                  — Wails 앱 진입점
├── app.go                   — AppService: JS 브릿지 메서드 (세션 기반)
├── session.go               — 인메모리 세션 (Masker XOR 마스킹 키 보관)
├── crypto.go                — USAG-Lib 래핑 (키 파생, 암복호화)
├── transfer.go              — 분할 업/다운로드 스트리밍 엔진
├── stream.go                — 로컬 미디어 스트리밍 HTTP 서버
└── frontend/                — 프론트엔드 (Wails embed)
    └── public/
        ├── index.html       — 변경 없음
        ├── css/             — 변경 없음
        ├── js/
        │   ├── app.js       — 변경 없음
        │   ├── core/
        │   │   ├── adapter.js   ← 교체 (Wails 브릿지 래퍼)
        │   │   ├── drive.js     ← 교체 (UI 상태만)
        │   │   ├── router.js    — 변경 없음
        │   │   └── utils.js     — 변경 없음
        │   ├── views/       — 변경 없음
        │   └── engine/
        │       ├── viewerjs.min.js  — 유지
        │       ├── viewerjs.min.css — 유지
        │       ├── Bencrypt.js      ← 제거
        │       ├── Opsec.js         ← 제거
        │       └── Bencode.js       ← 제거
        ├── sw.js            ← 제거
        └── icons/           — 변경 없음
```

---

## 4. Go 백엔드 설계

### 4.1 `session.go` — 인메모리 세션

```go
// Go 세션: 앱 수명 동안 인메모리로 마스킹 키 보관
// JS에 키는 절대 노출되지 않음
type Session struct {
    ServerUrl     string
    UserHash      string              // 서버 X-User-Hash 헤더용
    MaskedUserKey []byte              // Masker XOR 마스킹
    Folders       map[string]*FolderState
}

type FolderState struct {
    MaskedKey []byte                  // Masker XOR 마스킹
    Files     map[string]*FileState
}

type FileState struct {
    MaskedKey []byte                  // Masker XOR 마스킹
    OrigSize  int64
    FilePid   string                  // 서버 저장 ID (hex)
}
```

### 4.2 `app.go` — JS 브릿지 API

```go
type AppService struct {
    session *Session
    mask    *Bencrypt.Masker
    stream  *StreamServer
}

// ── 인증 (JS는 username/password 문자열만 전달) ──
func (a *AppService) Login(serverUrl, username, password string) (LoginResult, error)
// 내부: 키파생 → 서버 확인 → Go session에 마스킹 키 보관 → JS에 결과만 반환

func (a *AppService) Register(serverUrl, username, password, inviteCode string) error
func (a *AppService) Logout()
func (a *AppService) GetSavedCredentials() (SavedCreds, error)
func (a *AppService) SaveCredentials(username, password string) error
func (a *AppService) ChangePassword(newPassword string) error

// ── 서버 유틸 ──
func (a *AppService) FetchNotice() (string, error)

// ── 폴더 관리 (JS는 이름만, 키는 Go session) ──
func (a *AppService) GetFolderList() []string
func (a *AppService) CreateFolder(name string) error
func (a *AppService) RenameFolder(oldName, newName string) error
func (a *AppService) DeleteFolder(folderName string) error
func (a *AppService) UnlinkFolder(folderName string) error
func (a *AppService) TrimFolder(folderName string) (string, error)
func (a *AppService) ExportShareToken(folderName, password string) (string, error)
func (a *AppService) ImportShareToken(tokenText, password string) error

// ── 파일 목록 (JS는 표시용 메타만) ──
// FileEntry: { Name, Size, Ext, HasThumb } — 키 포함 안 함
func (a *AppService) SelectFolder(folderName string) ([]FileEntry, error)
func (a *AppService) RenameFile(folderName, oldName, newName string) error
func (a *AppService) DeleteFile(folderName, fileName string) error

// ── 미디어 (키는 Go session에서 자동 조회) ──
func (a *AppService) UploadFiles(folderName string, localPaths []string) error
// 진행률: Wails 이벤트 "upload:progress" 발송

func (a *AppService) DownloadFile(folderName, fileName, savePath string) error
// 진행률: Wails 이벤트 "download:progress" 발송

func (a *AppService) GetThumbnailDataURL(folderName, fileName string) (string, error)
// Go가 복호화 후 "data:image/jpeg;base64,..." 반환

func (a *AppService) GetStreamUrl(folderName, fileName string) (string, error)
// "http://127.0.0.1:{port}/stream/{token}" 반환

// ── 파일 선택 대화상자 ──
func (a *AppService) OpenFileDialog(multi bool) ([]string, error)
func (a *AppService) OpenFolderDialog() (string, error)
func (a *AppService) OpenSaveDialog(defaultName string) (string, error)
```

### 4.3 `transfer.go` — 분할 전송 엔진

**업로드 (로컬→서버):**
```
localFile → sm.EnFile(io.Reader) → io.Pipe → 16MiB POST chunks
                                             (X-Upload-Offset 헤더)
```

**다운로드 (서버→로컬):**
```
GET Range 16MiB chunks → 로컬 임시파일 순차 기록
임시파일 → sm.DeFile(io.Reader) → 출력 파일
임시파일 작업 완료/에러 시 즉시 삭제
```

### 4.4 `stream.go` — 로컬 미디어 스트리밍

- `127.0.0.1:{random_port}` HTTP 서버 (앱 수명 동안 유지)
- 등록: `(folderName, fileName)` → 일회성 토큰 발급, session 키 참조
- GET `/stream/{token}` 요청 시:
  1. 서버에서 GCMx1 청크 경계 기반으로 Range 다운로드
  2. 청크 복호화 (청크 정렬: 12B IV + N×1048592B)
  3. 복호화 스트림을 `Content-Range` 헤더와 함께 응답
- WebView에서 `<video src="http://127.0.0.1:{port}/stream/{token}">` 재생

---

## 5. 프론트엔드 교체 파일

### 5.1 `adapter.js` 교체 — 얇은 브릿지 래퍼

기존: `fetch()` + JS 암호화 라이브러리 import + Uint8Array 조작
변경: **Go 브릿지 단순 호출만** — 암호화/키 관련 코드 전혀 없음

```javascript
// ❌ 기존 (제거)
import { SHA3256, SymMaster, Masker } from '../engine/Bencrypt.js';
import { Opsec } from '../engine/Opsec.js';
const mask = new Masker();
async DeriveKeys(username, password) { /* argon2id JS 구현 */ }

// ✅ 변경 — Wails 자동 생성 바인딩 import
import { Login, Logout, GetFolderList, SelectFolder,
         UploadFiles, GetStreamUrl, GetThumbnailDataURL,
         ExportShareToken, ImportShareToken,
         OpenFileDialog, OpenSaveDialog }
         from '../../wailsjs/go/main/AppService.js';

export class AdapterService {
    async Login(serverUrl, username, password) {
        return await Login(serverUrl, username, password);
        // JS는 {ok, error} 결과만. 키는 Go session에만 존재
    }
    async GetThumbnailDataURL(folderName, fileName) {
        return await GetThumbnailDataURL(folderName, fileName);
        // Go가 복호화 후 "data:image/jpeg;base64,..." 반환
    }
    async GetStreamUrl(folderName, fileName) {
        return await GetStreamUrl(folderName, fileName);
        // "http://127.0.0.1:{port}/stream/{token}"
    }
    // ... 나머지도 동일 패턴
}
```

### 5.2 `drive.js` 교체 — UI 상태만

기존: `usrKey`, `currentFolderKey`, `flsMap` 등 Uint8Array 키 직접 관리
변경: **이름 문자열과 표시용 메타만**, 키는 Go session이 완전 담당

```javascript
// ❌ 기존 (제거) — 키/마스킹/암호화 상태
const mask = new Masker();
this.usrKey = null;           // 마스킹된 유저키 Uint8Array
this.currentFolderKey = null; // 마스킹된 폴더키 Uint8Array
this.flsMap = {};             // {파일명: 마스킹된 파일키}

// ✅ 변경 — 순수 UI 상태 (문자열/숫자만)
this.folderList = [];           // ["폴더1", "폴더2", ...]
this.currentFolderName = "";
this.currentFiles = [];         // [{Name, Size, Ext, HasThumb}]
this.isLoggedIn = false;
```

**업로드 플로우:**
```javascript
// 파일 선택 → Go에 경로 전달 → Go가 암호화+분할업로드
const paths = await OpenFileDialog(true);
await UploadFiles(this.currentFolderName, paths);
// 진행률 수신
window.runtime.EventsOn('upload:progress', ({fileIdx, percent}) => { ... });
```

**다운로드 플로우:**
```javascript
const savePath = await OpenSaveDialog(fileName);
await DownloadFile(this.currentFolderName, fileName, savePath);
```

**미디어 재생:**
```javascript
// Service Worker 없음 — Go localhost 스트리밍 URL 직접 사용
const url = await GetStreamUrl(folderName, fileName);
videoEl.src = url; // http://127.0.0.1:{port}/stream/{token}
```

---

## 6. 설정 관리

### 6.1 앱 설정 (`config.json`)

```json
{
  "serverUrl": "https://your-server.example.com",
  "theme": "system",
  "downloadDir": "",
  "chunkSizeMB": 16
}
```

위치: `AppData/MediaHub-desktop/config.json` (플랫폼별 OS 경로)
설정 UI: 로그인 화면에 서버 URL 입력 추가

### 6.2 자격증명 저장 (OS 키체인)

- Windows: Windows Credential Manager
- macOS: Keychain
- Linux: Secret Service
- Go 라이브러리: `github.com/zalando/go-keyring`

---

## 7. 구현 단계

### Phase 1 — 프로젝트 초기화
- [ ] Wails 프로젝트 생성 (`wails init`)
- [ ] `go.mod`에 USAG-Lib 의존성 추가
- [ ] 기존 `public/` 복사, JS 암호화 파일/sw.js 제거
- [ ] Wails embed 설정, `main.go` 기본 구조

### Phase 2 — Go 백엔드 핵심
- [ ] `crypto.go`: USAG-Lib 래핑 (키 파생, 암복호화 헬퍼)
- [ ] `session.go`: 인메모리 세션 (Masker XOR 키 보관)
- [ ] `transfer.go`: 분할 업로드/다운로드 엔진
- [ ] OS 자격증명 저장 연동

### Phase 3 — 로컬 미디어 스트리밍
- [ ] `stream.go`: localhost HTTP 스트리밍 서버
- [ ] GCMx1 청크 정렬 기반 Range 복호화
- [ ] 앱 시작 시 자동 포트 바인딩 + 토큰 관리

### Phase 4 — JS 브릿지 어댑터 교체
- [ ] `app.go`: 모든 JS 브릿지 메서드 구현 (세션 기반)
- [ ] `adapter.js`: Wails 바인딩 래퍼로 교체
- [ ] `drive.js`: UI 상태만 남기고 암호화 코드 제거
- [ ] 서버 URL 설정 UI (로그인 화면)
- [ ] Wails 이벤트 진행률 수신

### Phase 5 — 빌드 & 패키징
- [ ] `wails build` 단일 실행파일 생성
- [ ] 앱 아이콘 설정
- [ ] Windows/macOS 패키징 테스트

---

## 8. 핵심 기술 사항

### 8.1 GCMx1 청크 정렬 (스트리밍 복호화의 핵심)

GCMx1 암호화 파일 구조:
```
[GlobalIV 12B][Chunk0: 1MiB+16B][Chunk1: 1MiB+16B]...[ChunkN: rem+16B]
```
- `cipherChunkSize = 1,048,576 + 16 = 1,048,592`
- Range 재생 시 plainOffset → cipherOffset 변환:
  ```
  chunkIdx    = plainOffset / 1048576
  cipherStart = 12 + chunkIdx * 1048592
  ```
- 해당 청크 전체를 다운로드 후 복호화 → plainOffset 내 슬라이스 추출

### 8.2 메모리 안전 보장

```go
// 업로드: 스트리밍 (파일 전체 메모리 올리지 않음)
sm.EnFile(srcFile, fileSize, &chunkWriter{uploadFn})

// 다운로드: 임시파일 경유
tmp, _ := os.CreateTemp("", "mediahub-*.tmp")
defer os.Remove(tmp.Name())
// Range 청크 → tmp 기록 → sm.DeFile(tmp) → outFile
```

### 8.3 JS ↔ Go 데이터 규격 (키 없음)

| JS → Go | 타입 | 예시 |
|---------|------|------|
| 인증 | string | `"username"`, `"password"` |
| 파일 업로드 | string[] | `["/path/to/file.mp4"]` |
| 저장 경로 | string | `"/Downloads/file.mp4"` |

| Go → JS | 타입 | 예시 |
|---------|------|------|
| 로그인 결과 | `{ok, error}` | 키 없음 |
| 폴더 목록 | `string[]` | `["폴더1", "폴더2"]` |
| 파일 목록 | `FileEntry[]` | `[{Name, Size, Ext, HasThumb}]` |
| 썸네일 | string | `"data:image/jpeg;base64,..."` |
| 스트리밍 URL | string | `"http://127.0.0.1:PORT/stream/TOKEN"` |

**Go session 내부 (JS와 공유 안 함):**
```go
Session.MaskedUserKey  // XOR 마스킹 []byte
FolderState.MaskedKey  // XOR 마스킹 []byte
FileState.MaskedKey    // XOR 마스킹 []byte
```

---

## 9. 보안 고려사항

- **키가 JS에 노출되지 않음** — 모든 키/마스킹은 Go 프로세스 메모리 내부
- Go 측 민감 바이트: `sclear()` (`clear()` + `runtime.KeepAlive`)
- JS 브릿지 전달: 이름, 크기 등 표시용 메타데이터만
- 스트리밍 토큰: 일회성 랜덤 토큰, 재생 종료 후 해제
- 로컬 스트리밍 서버: `127.0.0.1` 바인딩 전용
- 임시 파일: 작업 완료/에러 즉시 삭제 (`defer os.Remove`)
- 앱 종료 시 session 메모리 sclear

---

## 10. 의존성

```
# Go
github.com/wailsapp/wails/v2
github.com/k-atusa/USAG-Lib/Bencrypt
github.com/k-atusa/USAG-Lib/Opsec
github.com/k-atusa/USAG-Lib/Bencode
github.com/zalando/go-keyring

# Frontend — 제거
❌ engine/Bencrypt.js
❌ engine/Opsec.js
❌ engine/Bencode.js
❌ sw.js (Service Worker)

# Frontend — 유지
✅ engine/viewerjs.min.js / .css
✅ views/*.js, core/router.js, core/utils.js
✅ CSS, HTML, 아이콘
```
