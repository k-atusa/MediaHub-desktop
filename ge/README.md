# MediaHub GE (Go Engine)

Wails v2 및 Go를 기반으로 개발된 MediaHub 데스크톱 애플리케이션 프로토타입입니다.  
기존 Python 기반 `pe` 엔진 대비 빠른 구동 속도와 적은 리소스 사용량을 목표로 합니다.

---

## 📁 프로젝트 구조

```text
ge/
├── run.bat                # 개발 모드 원클릭 실행 스크립트 (더블 클릭)
├── build.bat              # 프로덕션 빌드 스크립트 (ge.exe 생성)
├── app.go                 # 백엔드 App 구조체 및 비즈니스 로직 (Greet, GetSystemInfo 등)
├── main.go                # Wails 앱 초기화 및 웹뷰 윈도우 설정
├── wails.json             # Wails 프로젝트 메타데이터 및 설정 파일
├── go.mod / go.sum        # Go 모듈 및 의존성 정의
└── frontend/
    └── dist/              # 프론트엔드 정적 웹 리소스 (Go 바이너리에 자동 임베드)
        ├── index.html     # 메인 UI
        ├── style.css      # 스타일시트 (다크 테마)
        └── main.js        # Go IPC 통신 연동 스크립트
```

---

## 🚀 실행 및 빌드 방법

### 가장 간편한 방법: 스크립트 실행
- **실행 (개발 모드)**: `ge/run.bat` 더블 클릭
- **빌드 (배포 모드)**: `ge/build.bat` 더블 클릭

---

### 터미널에서 직접 실행할 때 (중요: 빌드 태그 안내)

Wails v2는 `desktop`과 함께 실행 모드(`dev` 또는 `production`) 태그가 동시에 전달되어야 합니다.  
PowerShell에서는 쉼표가 구분자로 인식되므로 반드시 따옴표(`"..."`)로 묶어야 합니다.

#### 1. 개발 모드로 실행 (개발자 도구 / F12 지원)
```powershell
cd ge
go run -tags "desktop,dev" .
```

#### 2. 프로덕션 실행 파일 빌드
```powershell
cd ge
go build -tags "desktop,production" -ldflags="-w -s -H windowsgui" -o ge.exe .
.\ge.exe
```
