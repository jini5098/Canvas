# Canvas 배포 체크리스트

## 1. 데이터베이스

- [ ] Supabase 프로젝트를 백업하거나 복구 지점을 확인했다.
- [ ] `supabase/migrations/202609060001_secure_workspace.sql` 전체를 실행했다.
- [ ] SQL 실행 결과에 오류가 없다.
- [ ] 기존 회원에게 `profiles` 행이 만들어졌는지 확인했다.
- [ ] 소유자 UUID를 확인해 아래 명령을 **한 번만** 실행했다.

```sql
update public.profiles
set role = 'admin'
where id = '<소유자 계정 UUID>';
```

- [ ] 기존 작품의 `owner_id`가 가능한 범위에서 옮겨졌는지 확인했다.
- [ ] `canvas-artworks` Storage 버킷이 만들어졌는지 확인했다.

## 2. 인증과 실시간 기능

- [ ] Authentication → URL Configuration의 Site URL이 `https://jini5098.github.io/Canvas/`이다.
- [ ] 같은 주소가 Redirect URLs에도 포함되어 있다.
- [ ] Realtime Settings에서 **Allow public access**를 껐다.
- [ ] 이메일 가입 정책(확인 메일 사용 여부)을 원하는 방식으로 정했다.

## 3. 배포와 품질 확인

- [ ] `npm test`가 통과했다.
- [ ] GitHub Actions의 `Canvas quality checks`가 통과했다.
- [ ] 데스크톱과 모바일에서 게스트 로컬 캔버스를 확인했다.
- [ ] 회원가입 → 확인 → 로그인 → 새로고침 → 로그아웃 흐름을 확인했다.
- [ ] 두 계정으로 공개방 입장, 펜, 채팅, 참여자, 초기 그림 동기화를 확인했다.
- [ ] 비공개방의 오답/정답 비밀번호를 각각 확인했다.
- [ ] 방장이 아닌 사용자의 강퇴·타이머·공개 설정 변경이 거절되는지 확인했다.
- [ ] 방장이 강퇴와 타이머를 정상 실행할 수 있는지 확인했다.
- [ ] 저장한 그림이 로컬 다운로드와 내 보관함에 모두 나타나는지 확인했다.
- [ ] 오프라인 상태에서 이전에 연 게스트 화면 셸이 다시 열리는지 확인했다.
