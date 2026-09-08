# Canvas — Live Workspace

실시간 공동 드로잉, 채팅, 커뮤니티, 작품 보관함을 한곳에 모은 웹 워크스페이스입니다. 모바일·펜 입력을 포함한 반응형 캔버스와 공개/비공개 협업방을 지원합니다.

## 이번 수정의 핵심

- 새로고침 뒤 로그인 세션 복구와 실제 로그아웃
- 게스트의 온라인 기능을 차단하고 로컬 체험 캔버스로 분리
- 방 비밀번호를 서버의 bcrypt 해시로만 보관
- 방 생성·입장·강퇴·공개 전환·타이머·관리자 차단을 서버 RPC에서 검증
- 비공개 Supabase Realtime 채널과 서버 전용 채팅/제어 채널 적용
- Realtime Presence와 계정 UUID 기반 참여자 식별
- 큰 캔버스 이미지를 32KB 조각으로 나누어 안전하게 동기화
- 화면 크기와 관계없이 정확한 Pointer Events 좌표 변환
- 게시글·댓글·채팅·작품·관리자 화면의 동적 HTML 주입 제거
- 사용자 UUID별 저장소 경로와 RLS 정책 적용
- GitHub Pages 하위 경로에 맞춘 PWA manifest와 서비스 워커 복구
- 자동 회귀 테스트와 GitHub Actions 추가

자세한 원인과 수정 내역은 [CANVAS_ERROR_REPORT.md](./CANVAS_ERROR_REPORT.md)에 있습니다.

## 배포 전 필수 설정

프런트엔드와 데이터베이스 마이그레이션은 한 세트입니다. 오래된 데이터베이스 상태에서 새 프런트엔드만 먼저 배포하지 마세요.

1. Supabase SQL Editor에서 `supabase/migrations`의 SQL 파일을 번호 순서대로 실행합니다.
2. `profiles`에서 사이트 소유자 계정 한 명의 `role`을 `admin`으로 지정합니다.
3. Supabase **Realtime Settings**에서 **Allow public access**를 끕니다.
4. Authentication의 Site URL과 Redirect URL에 실제 GitHub Pages 주소를 등록합니다.
5. `npm test`가 모두 통과하는지 확인한 다음 GitHub에 배포합니다.

마이그레이션은 기존 행을 삭제하지 않습니다. 적용 직전 자료는 접근이 잠긴 `canvas_backup_20260906` 스키마에 보관하며, 예전 방 비밀번호는 원문이 아닌 bcrypt 해시로만 백업·이전됩니다. 기존 `rooms` 테이블은 이전 뒤 모든 클라이언트 권한이 제거됩니다.

구체적인 확인 순서는 [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md)를 따르세요.

## 로컬 확인

```bash
npm test
python3 -m http.server 8080
```

브라우저에서 `http://localhost:8080`을 엽니다. Supabase 로그인·실시간 기능은 허용된 Redirect URL과 데이터베이스 마이그레이션이 준비되어야 완전하게 동작합니다.

## 보안 메모

브라우저에 포함된 Supabase publishable key는 공개 클라이언트 식별자입니다. 데이터 보호는 키를 숨기는 방식이 아니라 Auth, RLS, 비공개 Realtime 정책으로 수행합니다. `service_role` 또는 secret key는 이 저장소에 넣지 마세요.
