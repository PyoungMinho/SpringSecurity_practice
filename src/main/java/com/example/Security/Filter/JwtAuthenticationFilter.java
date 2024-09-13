package com.example.Security.Filter;

import com.example.Security.Jwt.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean { // 클라이언트의 요청에서 JWT 토큰을 추출하고, 이를 JwtProvider를 통해 검증한 후 사용자 정보를 설정하는 필터입니다.
    /* JwtAuthenticationFilter 주요기능
    HTTP 요청에서 Authorization 헤더를 읽고, JWT 토큰을 추출.
    추출한 토큰을 JwtProvider로 검증.
    토큰이 유효하면 해당 토큰에서 사용자 정보를 추출하여 인증 객체(Authentication)를 생성하고, SecurityContext에 저장.*/

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // 1. Request Header에서 JWT 토큰 추출
        String token = resolveToken((HttpServletRequest) request);

        // 2. 토큰 존재 여부 확인
        if (token == null) {
            // 로그 기록 (선택 사항)
            logger.warn("JWT Token is missing in the request header.");
        }

        // 3. validateToken으로 토큰 유효성 검사
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // 토큰이 유효할 경우 Authentication 객체를 만들어서 SecurityContext에 저장
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            // 토큰 유효성 검사 실패 로그 (선택 사항)
            if (token != null) {
                logger.warn("Invalid JWT Token.");
            }
        }
        // 4. 필터 체인 계속 실행
        chain.doFilter(request, response);
    }

    // Request Header에서 토큰 정보 추출
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        String bearer = "Bearer ";
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(bearer)) {
            return bearerToken.replace(bearer, "");
        }
        return null;
    }
}
