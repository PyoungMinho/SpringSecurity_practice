package com.example.Security.Config;

import com.example.Security.Filter.JwtAuthenticationFilter;
import com.example.Security.Jwt.JwtTokenProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // 메서드 수준 보안을 위해 필요할 경우 추가
@RequiredArgsConstructor
public class SecurityConfig { //역할: Spring Security의 전반적인 보안 설정을 담당합니다. 특히, JWT와 연관된 필터와 인증 방식을 구성하고, 어떤 요청이 보호되고 어떤 요청이 열려있는지를 정의합니다.

    /* SpringSecurityConfig 주요설정 및 작동
    JwtAuthenticationFilter가 인증 필터 체인에 추가됩니다.
    특정 경로에 대한 인증을 요구하는지, 로그인 및 로그아웃 처리를 어떻게 할지 설정.
    어떻게 작동하는가: 이 설정을 통해 Spring Security는 JWT를 사용하는 인증 방식으로 구성됩니다.
                   JwtAuthenticationFilter는 필터 체인에 등록되어 매 요청마다 JWT 토큰을 검증하고,
                   설정된 경로 보호 규칙에 따라 보호된 경로에 접근할 때 인증을 강제합니다.*/
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
        //  사용자 인증 직전 단계에 위치하여 아래와 같은 기능을 주로 한다.
    }

    @Bean // 특정 경로에 대한 검증을 하는 필터
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                // REST API이므로 basic auth 및 csrf(session을 사용안해서 필요가 없음으로)보안을 사용하지 않음
                .httpBasic(AbstractHttpConfigurer::disable) //httpBasic 은 사용자명 비밀번호를 텍스트로 전송하는 가장 기본적인 인증 방식이다.
                                                            // 하지만 보안에 취약, JWT와 같이 암호화된 토큰 기반의 인증 방식을 사용할 때는 disable() 한다.
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                // JWT인증 방식을 사용하기 때문에 세션을 생성할 필요가 없기 때문에 STATELESS로 관리한다.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        // 해당 API에 대해서는 모든 요청을 허가
                        .requestMatchers("/members/sign-in").permitAll()
                        // USER 권한이 있어야 요청할 수 있음
//                        .requestMatchers("/members/test").hasRole("USER") // Role_USER로 변환된다
                        .requestMatchers("/members/test").hasAuthority("USER") // USER 그대로 확인가능
                        // 그 외 모든 요청에 대해 인증을 요구
                        .anyRequest().authenticated()
                )
                // JWT 인증을 위한 필터 추가 (UsernamePasswordAuthenticationFilter 이전에 실행)
                // 로그인 경로로 POST 요청이 들어오면 UsernamePasswordAuthenticationFilter로 내부에 아이디와 비밀번호를 전달한 후에 검증
                // 검증을 하는 방법은 DB안에 있는 User 정보를 꺼내와서 UserDetailService가 UserDetails 객체에 담아서 Authentication Manager에서 검증
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
                // 커스텀 에러 핸들링
                .exceptionHandling(exception -> exception
                        // 권한이 없을 때 (403) 커스텀 처리
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.getWriter().write("Access Denied: 403Error.");
                        })
                        // 인증되지 않은 사용자가 접근할 때 (401)
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("Unauthorized: 401Error.");
                        })
                )
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt Encoder 사용
        return new BCryptPasswordEncoder();
    }
}
