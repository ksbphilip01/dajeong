# 다정 (지역 선한 소식 플랫폼) — 웹앱

인스타그램형 커뮤니티. 단체·개인 참여자가 재능기부·봉사·기부·나눔 소식을 올리고 서로 응원합니다.
프론트엔드는 정적 HTML 한 장(`public/index.html`), 백엔드는 Supabase(Auth + Postgres + Storage)입니다.

## 1. Supabase 준비 (5분)
1. supabase.com → New project (Region: Northeast Asia/Seoul, Free)
2. **SQL Editor** → `supabase/schema.sql` 내용 전체 붙여 넣고 **Run**  
   - 테이블 `docs`(문서 저장소), `profiles`, `admins`, 권한(RLS) 정책, RPC, 스토리지 버킷 `media`가 만들어집니다.
   - 여러 번 실행해도 안전합니다.
3. **Authentication → Providers → Email**: 켜져 있는지 확인. 테스트 중엔 *Confirm email* 을 꺼 두면 가입 즉시 로그인됩니다.
4. **Project Settings → API** 에서 `Project URL` 과 `anon public` 키를 복사 → `public/config.js` 에 입력.
5. **첫 번째로 가입하는 계정이 자동으로 관리자**가 됩니다. 관리자를 더 두려면 SQL Editor에서  
   `insert into public.admins(user_id) select id from auth.users where email='someone@example.com';`

## 2. 로컬에서 열어 보기
```
cd public && python3 -m http.server 8080
```
브라우저에서 http://localhost:8080

## 3. Render 배포 (무료 정적 사이트)
1. 이 폴더를 GitHub 저장소에 올립니다.
2. Render → **New → Blueprint** → 저장소 선택 → `render.yaml` 감지 → Apply.  
   (또는 New → Static Site, Publish directory = `public`)
3. 배포 주소(예: `https://dajeong.onrender.com`)가 나오면 Supabase **Authentication → URL Configuration** 의 *Site URL* 과 *Redirect URLs* 에 그 주소를 추가합니다. (비밀번호 재설정 메일 링크용)
4. 커스텀 도메인은 Render → Settings → Custom Domains 에서 연결.

## 4. 이름·도시 바꾸기
`public/config.js` 의 `BRAND`, `CITY`, `TAGLINE` 만 바꾸면 상단 로고와 가입 화면이 바뀝니다.  
본문 안내문에 남아 있는 "다정여수" 문구는 `index.html` 에서 찾아 바꾸기 하세요.

## 구조
- `public/index.html` — 앱 전체 (UI + 로직)
- `public/adapter.js` — 앱이 쓰는 문서형 DB API를 Supabase로 연결하는 어댑터 (실시간 반영, 인증, 스토리지, 다운로드)
- `public/config.js` — 설정
- `supabase/schema.sql` — DB 스키마·권한·RPC

## 데이터 모델 (요약)
모든 콘텐츠는 `docs(collection, id, data jsonb)` 한 테이블에 들어갑니다.
`orgs`, `posts`, `comments`, `stories`, `people`(좋아요·저장·친한친구·차단·참여), `dms`/`dms/<id>/msgs`, `reports`, `mod`(승인·숨김·인증), `notices`.
권한은 `doc_can_read / doc_can_write / doc_can_modify` 함수가 컬렉션별로 판정하고, 관리자는 `admins` 테이블로 결정됩니다.
