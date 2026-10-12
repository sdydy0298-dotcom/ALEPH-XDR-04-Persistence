# ALEPH XDR-04 · 몰래 심어진 프로그램을 찾아냅니다

**서명 없는 신규 서비스·낯선 예약 작업·시작 폴더 변경**을 Wazuh 형식의 로그에서 분석해, 명확한 지속성(Persistence) 흔적만 임시 격리하는 독립형 보너스 과제입니다.

**공개 결과물:** https://sdy-xdr-04.vercel.app  
**GitHub:** https://github.com/sdydy0298-dotcom/ALEPH-XDR-04-Persistence

> 교육용 **가상 Wazuh 경보 24건**과 파일 기반 **ZTNA 실습 판정기**를 사용합니다. 웹사이트는 정적 분석 결과를 보여 주는 데모이며, 운영 중인 실제 PC·네트워크를 격리하거나 실시간 Wazuh와 연결하지 않습니다.

## 원본과 재현 방법

- 공식 원본: [ChoiTimo/aleph-defense-starter/xdr/fixtures/persistence.json](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/xdr/fixtures/persistence.json) (**수정 없이 복제**)
- 공식 실행기: [scripts/xdr-run.mjs](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/scripts/xdr-run.mjs) (**수정 없이 복제**)
- 원본 규격: `aleph.xdr.fixture.v1`, 출력 규격: `aleph.xdr.result.v1`

```bash
npm run xdr:run -- persistence
npm test
npm run build
```

공식 교육용 예시를 대상으로 자체 판정한 건수는 **BLOCK 8 / ALERT 8 / RECORD 8**, 정상 이벤트 오차단 **0건**입니다. 실제 비공개 심판 정답표는 제공되지 않으므로 최종 채점 점수는 제출 후 확인해야 합니다.

## 제작 단계별 구현

| 단계 | 경로 | 직접 확인 |
|---|---|---|
| 1 · 경보 읽기 | `xdr/persistence/read-alerts.mjs` | 원본 24건 → 요약 24줄, 계정·출발 IP·규칙 수준·설명·시각만 출력, 민감 문자열 마스킹 |
| 2 · 패턴 목록 | `xdr/persistence/patterns.json` | MITRE T1543, T1053 근거 및 시작 폴더의 T1547.001 구분 |
| 3 · 판정 모듈 | `xdr/persistence/decide.mjs` | **import 없는 독립 `decide(alert)`**, 파일·네트워크 접근 없음, 0.85↑ BLOCK / 0.50↑ ALERT / 미만 RECORD |
| 4 · 알림 및 격리 | `xdr/persistence/respond.mjs` | 공격 경보만 **15분 거부 규칙 8개**, 알림 **16줄** 저장 |
| 5 · 시험 실행 | `xdr/run.mjs`, `xdr/persistence/result.json` | 공식 실행기 출력, 세 분류 건수, 정상 PC 통과 및 만료 이후 허용 |
| 제출 확인 | `.github/workflows/check.yml` | 자동 재실행 → 테스트 → 재실행 → 빌드 → 산출물 일치 확인 |

### 판정 기준

- **BLOCK:** 높은 Wazuh 수준과 함께 미서명 신규 서비스 등록, 의심스러운 임시 폴더의 예약 작업, 평소 목록에 없는 시작 폴더 자동실행 프로그램, 서비스·예약 작업의 복합 지속성 증거가 확인됨
- **ALERT:** 수업 중 만든 예약 작업, 서명 미확인, 서비스 설명만 변경, 임시 파일만 생성 등 추가 분석이 필요하지만 악성 설치가 확정되지 않음
- **RECORD:** 기존의 서명된 서비스, 평소 운영체제 업데이트, 일반 로그인·로그아웃 등 정상 작업

서비스/예약 작업은 **MITRE ATT&CK T1543 및 T1053**이고, 시작 폴더 지속성의 정확한 기술 분류는 **T1547.001**입니다. 원본 교육용 경보의 T1543 표기는 그대로 유지하되 패턴 설명에서는 구분합니다.

### 응답 정책

판단은 `decide.mjs`만 담당하고, 알림/거부 파일 쓰기는 `respond.mjs`만 담당합니다. `ztna/rules.json`은 원래의 허용·거부 정책으로 보존되며 **수정되지 않습니다**. `ztna/evaluate.mjs`가 15분 동안만 유효한 `xdr/temporary-deny.json`과 기존 정책을 함께 읽어 접근을 판정합니다.

각 규칙은 `alertId` 증거, 출발 주소, 생성·만료 시각, 이유를 가집니다. 정상·애매한 경보에는 임시 격리 규칙을 만들지 않습니다. 교육용 경보의 출발 IP가 해당 PC를 나타낸다고 가정합니다. 운영 환경에서는 NAT 공유 IP를 기준으로 PC를 격리하면 다른 사용자까지 차단될 수 있으므로 실제 단말 ID·신원 기반 정책이 필요합니다.

### 보안·공개 범위

실제 접근 토큰, 비밀번호, 쿠키, 관리자 자격 증명은 사용하지 않습니다. 출력은 미리 준비한 **가상 경보 데이터**에 한정합니다. 테스트 기준 시각은 재현성을 위해 고정한 `2026-10-13T00:00:00.000Z`이며 실제 현재 시각이 아닙니다. 웹사이트의 `decide()` 재실행은 브라우저 내부 계산으로 서버 접근 정책을 변경하지 않습니다.

**XDR-01~XDR-03의 저장소나 배포는 수정하지 않았습니다.**
