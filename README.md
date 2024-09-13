# Spring Security 와 JWT를 사용한 로그인

## 로그인 시:

### 클라이언트가 로그인 요청을 보냅니다 → SpringSecurityConfig에서 설정한 로그인 로직을 따라 로그인 성공 → JwtProvider가 사용자 정보를 바탕으로 JWT 토큰을 생성 → 클라이언트에게 JWT 토큰이 반환됨.

---

## 인증된 요청 시:

### 클라이언트가 요청을 보낼 때 JWT 토큰을 포함 → JwtAuthenticationFilter가 요청에서 JWT를 추출하고 검증 → JwtProvider를 통해 토큰의 유효성을 검사하고 사용자 정보를 추출 → SecurityContext에 사용자 인증 정보를 설정 → 이후의 요청은 인증된 상태로 처리됨.

