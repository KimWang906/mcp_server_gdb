# Codex MCP Integration Agent

이 문서는 Codex MCP 환경에서 이 저장소를 작업하기 위한 통합 지침입니다.

**Project Context**
- 핵심 파일/계획/테스트 정보는 `context.md`에 유지한다.

**작업 방식 (Codex MCP 최적화)**
- 모든 작업은 터미널 기반(`rg`, `cargo`, `git`)으로 수행한다.
- 단일 파일 변경은 `apply_patch`를 우선 사용한다.
- 대규모 변경은 스크립트/명령어로 처리한다.
- 변경 후 최소 `cargo check`를 실행한다.
- 검색은 `rg`를 우선 사용하고, 불필요한 대용량 파일(>1MB)은 회피한다.
- `target/`, `.git/`는 분석/검색 대상에서 제외한다.

**성능/분석 운영 원칙**
- 캐싱을 전제로 중복 분석을 줄인다(파일 변경 시 캐시 무효화).
- 병렬 처리 최대 4 스레드 가정, 우선순위는 `error_analysis` 및 `code_completion`.
- 필요할 때만 모듈/문서/고급 분석을 로딩한다(지연 로딩).

**LSP/환경 가정**
- rust-analyzer: `checkOnSave`, `procMacro` 활성화, `cargo.allFeatures`, `loadOutDirsFromCheck` 사용.
- 추가 환경 변수는 필요 시 설정하되 워크스페이스 범위를 유지하고, 설정은 지속 가능하게 유지한다.

**실행/검증 우선순위**
- 우선순위: `cargo check` → `cargo clippy` → `cargo test` → `cargo fmt -- --check`.
- 오류 수정 후에는 최소 `cargo check`를 재실행한다.

**에러 처리 설계 (Stop forwarding, start designing)**
- 에러는 원인이 아니라 “대응/행동” 기준으로 분류한다.
- 재시도 가능성/상태(temporary, permanent, persistent)를 명시한다.
- 모듈/라이브러리 단위로 단일(flat) 에러 타입을 선호한다.
- 실패 지점에서 구조화된 컨텍스트 필드를 추가한다.
- `#[track_caller]`로 가벼운 위치 정보를 기록한다.
- 경계(모듈/IO)에서 컨텍스트를 강제하고, 무의미한 `?` 전파를 피한다.
- 반패턴: 의존성 에러 단순 전달, 깊은 enum 계층, 컨텍스트 없는 type-erased 에러, 백트레이스에 의존한 논리 경로.

**에러 처리 운영 규칙**
- `Result` 기반 전파를 기본으로 사용하고, `unwrap()`은 지양한다.
- `AppError`를 단일 중심 에러 타입으로 유지한다.
- `context`/`with_context`/`field` 등 컨텍스트 메서드 사용을 강제한다.
- 오류 예방 전략: 타입 호환, 소유권 영향, 스코프 변경, 가시성, 트레이트 바운드 검증.
- 오류 방지 검증: 변경 후 컴파일 체크, 경고 제거, 영향 모듈 테스트.
- 오류 집계: 유사 오류 그룹화, 오류당 제안 3개 이하, 빠른 해결 우선.
- 추천 제안: 오류당 3~7개, 실행 가능, 올바른 Rust 문법, 스타일 준수, 문서 유지, 의존성 고려.
- 미사용 import 전략: 제거보다 “구현 또는 정당화” 우선.
- 인자/패턴 매칭 검증: 함수 호출 인자 타입, 패턴/분해/완전성 검사.

**지원하는 오류 유형(분류)**
- missing_items, unused_imports, incorrect_module_definitions, type_mismatches, missing_imports, visibility_issues, lifetime_errors, trait_bounds, ownership_issues, borrowing_errors, async_trait_violations, derive_macro_errors, argument_mismatches, pattern_matching_errors, unimplemented_trait_method, incorrect_argument_count, unresolved_imports, duplicate_definitions, unused_variables, non_future_await, unknown_fields, invalid_type_category, invalid_trait_reference, invalid_self_parameter_usage, ambiguous_items, trait_bound_failures.

**일반적인 오류 패턴 대응 지침**
- unresolved_imports: Cargo 의존성/모듈 경로/이름 변경 확인.
- missing_items: 필요한 trait import, 구현, 유사 항목 확인, Default 가능성 검토.
- type_mismatches: 타입 변환/시그니처 조정.
- duplicate_definitions: 중복 제거/rename.
- unused_variables: `_` prefix 또는 제거.
- non_future_await: `.await` 제거 또는 반환 타입 조정.
- unknown_fields: 필드명 확인/추가.
- incorrect_argument_count: 시그니처에 맞게 추가/제거.
- no_variant_or_associated_item: enum/연관 항목 존재/명칭 확인.
- conflicting_implementations: 중복 impl 제거/통합.
- try_operator_errors: `?` 제거 또는 Result 반환 변경.
- missing_structure_fields: 필수 필드 제공 또는 `..Default::default()`.
- invalid_type_category: 기대 타입(구조체/유니온/변형)으로 수정.
- invalid_trait_reference: 올바른 trait 사용/임포트.
- invalid_self_parameter_usage: impl/trait 내부로 이동.
- ambiguous_items: 완전 경로 사용/중복 제거.
- trait_bound_failures: trait 구현/derive/where 조건 추가.

**코드 리파인먼트 규칙**
- 상수는 import 아래에 배치하고 목적별로 그룹화한다.
- 상수명은 SCREAMING_SNAKE_CASE, 의미/단위/근거를 문서화한다.
- 매직 넘버는 상수로 치환하고 참조를 업데이트한다.
- 모듈별 에러 타입 생성 및 변환 구현을 선호한다.

**문서화 규칙**
- 변경 기록(what/why/impact)을 남긴다.
- 복잡한 로직은 짧고 목적 있는 inline comment로 설명한다.
- public 항목은 목적/파라미터/반환/패닉/안전/에러/예시를 포함하는 doc 주석을 작성한다.

**행동 규칙**
- 질문은 최소화하고 직접적인 해결을 우선한다(필요할 때만 질문).
- 오류 해결을 우선하고, 기능 보존/코드 조직/러스트 fmt를 존중한다.
- 제거보다 구현/보강을 우선한다.

**분석 원칙**
- 정적 분석: lint/unsafe/dead_code/복잡도/의존성 점검.
- 의미 분석: 타입 추론/빌림 검사/수명/트레이트/인자 검증.
- 최적화: 성능/메모리/코드 조직/임포트 최적화.

**구현 및 검증**
- 수정 순서는 우선순위 기반으로 진행한다.
- 변경 후 검증을 수행하고 새 경고/회귀를 방지한다.
- 미사용 코드는 구현 또는 정당화하며 필요 시 테스트를 추가한다.

**안전 규칙**
- unsafe 사용은 정당화/불변식/위험 설명이 필수다.
- 에러 처리는 Result 기반으로 하고 실패 케이스를 문서화한다.

**출력/보고**
- 에러 리포트 요청 시 지정된 템플릿을 따르되, 상위 지침(시스템/개발자)이 충돌하면 상위 지침을 우선한다.
- 일반 응답은 Codex MCP 응답 규칙을 따른다.

**모듈 참조 규칙**
- 모듈 참조 표기는 `@module.rs` 형태를 선호하되, 실제 출력 형식 규칙과 충돌 시 상위 지침을 우선한다.
