package com.example.Security.Controller;

import com.example.Security.Dto.JwtToken;
import com.example.Security.Dto.SingInDto;
import com.example.Security.Service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/sign-in")
    public JwtToken signIn(@RequestBody SingInDto singInDto) {
        String username = singInDto.getUsername();
        String password = singInDto.getPassword();
        log.info("signIn : {}, PWD : {} ", username, password);

        JwtToken jwtToken = memberService.signIn(username, password);
        log.info("jwtToken accessToken = {}, refreshToken = {}", jwtToken.getAccessToken(), jwtToken.getRefreshToken());

        return jwtToken;
    }

    @PostMapping("/test")
    public String test() {
        return "success";
    }
}
