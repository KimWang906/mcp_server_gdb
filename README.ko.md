# MCP Server GDB

MCP 프로토콜 기반의 GDB/MI 서버로, AI 어시스턴트와 함께 원격 디버깅을 수행할 수 있습니다.

## 기능

- GDB 디버그 세션 생성/관리
- 브레이크포인트 설정/관리
- 스택 정보 및 변수 조회
- 프로그램 실행 제어(실행, 일시정지, 스텝 등)
- 동시 다중 세션 디버깅 지원
- 에이전트 동작을 확인해 프롬프트를 개선할 수 있는 내장 TUI (WIP)

## 설치

### 미리 빌드된 바이너리
릴리즈 페이지에서 플랫폼에 맞는 바이너리를 내려받아 실행할 수 있습니다.

### 소스에서 빌드
레포지토리를 클론한 뒤 cargo로 빌드합니다.
```bash
cargo build --release
cargo run
```

### Nix 사용
Nix가 설치되어 있다면 클론 없이 실행할 수 있습니다.

#### 로컬 실행(클론 이후)
```bash
nix run .
```

#### GitHub에서 원격 실행
```bash
nix run "git+https://github.com/pansila/mcp_server_gdb.git" -- --help

```

#### 개발 환경
모든 의존성이 포함된 개발 쉘로 진입합니다.
```bash
nix develop
```

## 사용법

1. 직접 실행: `./mcp-server-gdb`
2. 두 가지 전송 모드를 지원합니다:
   - Stdio (기본): 표준 입출력 기반
   - SSE: Server-Sent Events 기반, 기본 주소 `http://127.0.0.1:8080`

### CLI 옵션

```bash
./mcp-server-gdb \
  --log-level info \
  --transport stdio|sse \
  --enable-tui
```

- `--enable-tui` 사용 시 `--transport sse`가 필요합니다(키 이벤트 유실 방지).

### TUI

실행 방법:

```bash
./mcp-server-gdb --enable-tui --transport sse
```

키 바인딩:
- `Tab`: 뷰 모드 순환
- `F1..F7`: 전체, 레지스터, 스택, 명령어, 출력, 매핑, 헥스덤프
- `j/k`: 아래/위 스크롤 (출력/매핑/헥스덤프)
- `J/K`: 페이지 아래/위 (출력/매핑/헥스덤프)
- `g/G`: 맨 위/맨 아래 (출력/매핑/헥스덤프)
- `H/T`: 힙/스택을 헥스덤프로 로드 (헥스덤프 뷰)
- `q`: TUI 종료

## 설정

`src/config.rs` 또는 환경 변수로 다음 항목을 설정할 수 있습니다:

- 서버 IP 주소
- 서버 포트
- GDB 커맨드 타임아웃(초)

## 지원 도구

### 핵심 MCP 도구 (MI 기반)

**세션 관리**
- `create_session` - GDB 디버깅 세션 생성(프로그램/인자/PTY 등 선택)
- `get_session` - 세션 ID로 조회
- `get_all_sessions` - 모든 세션 목록
- `close_session` - 세션 종료

**디버그 제어**
- `start_debugging` - 디버깅 시작
- `stop_debugging` - 디버깅 종료
- `continue_execution` - 실행 계속
- `step_execution` - 다음 라인으로 스텝 인
- `next_execution` - 다음 라인으로 스텝 오버

**브레이크포인트**
- `get_breakpoints` - 브레이크포인트 목록
- `set_breakpoint` - 브레이크포인트 설정
- `delete_breakpoint` - 브레이크포인트 삭제(복수 가능)

**디버그 정보**
- `get_stack_frames` - 스택 프레임 조회
- `get_local_variables` - 프레임의 로컬 변수 조회
- `get_registers` - 레지스터 조회(선택적 인덱스 리스트)
- `get_register_names` - 레지스터 이름 조회(선택적 인덱스 리스트)
- `read_memory` - 주소/범위로 메모리 바이트 읽기

**입출력**
- `execute_cli` - 세션에서 GDB/GEF CLI 명령 실행
- `get_inferior_output` - PTY에서 하위 프로세스 출력 읽기
- `send_inferior_input` - PTY로 하위 프로세스 입력 전송

### GEF 패스스루 도구

아래 도구는 GEF CLI 명령으로 전달됩니다(선택적으로 `args` 사용 가능).

**보안**
- `checksec` - 바이너리 mitigations 확인
- `canary` - 스택 카나리 값 표시
- `aslr` - ASLR 상태 표시
- `pie` - PIE 정보 표시

**메모리**
- `vmmap` - 메모리 매핑 표시
- `memory` - 메모리 조회/수정
- `hexdump` - 메모리 헥스덤프
- `dereference` - 포인터 역참조
- `xinfo` - 주소 정보 표시
- `xor-memory` - 메모리 XOR

**힙**
- `heap` - 힙 구조 확인
- `heap-analysis-helper` - 힙 분석 도우미

**ELF / 바이너리**
- `elf-info` - ELF 정보 표시
- `got` - GOT 엔트리 표시
- `xfiles` - 로드된 파일 목록

**검색**
- `search-pattern` - 메모리 패턴 검색
- `scan` - 메모리 값 스캔
- `pattern` - 패턴 생성/검색

**패치**
- `nop` - NOP 패치
- `patch` - 메모리 패치
- `stub` - 함수 스텁 처리

**실행 제어**
- `entry-break` - 엔트리 브레이크
- `name-break` - 이름으로 브레이크 설정
- `skipi` - 명령 스킵
- `stepover` - 명령 스텝 오버
- `trace-run` - 실행 트레이스

**프로세스**
- `process-status` - 프로세스 상태 표시
- `process-search` - 프로세스 검색
- `hijack-fd` - 파일 디스크립터 하이재킹

**기타**
- `context` - 컨텍스트 표시
- `registers` - 레지스터 표시
- `arch` - 아키텍처 정보 표시
- `eval` - 표현식 평가
- `print-format` - 출력 포맷 옵션 표시
- `format-string-helper` - 포맷 스트링 도우미
- `pcustom` - 커스텀 구조체 출력
- `reset-cache` - GEF 캐시 리셋
- `shellcode` - 셸코드 생성
- `edit-flags` - 플래그 편집
- `functions` - GEF 함수 목록

**GEF 헬퍼 함수**
- `gef_base` - `$_base()` 평가
- `gef_stack` - `$_stack()` 평가
- `gef_heap` - `$_heap()` 평가
- `gef_got` - `$_got()` 평가
- `gef_bss` - `$_bss()` 평가

참고: 전체 도구 및 파라미터는 `src/tools.rs`에 정의되어 있습니다.

## 라이선스

MIT
