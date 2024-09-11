package com.example.Security.Service;

import com.example.Security.Dto.JwtToken;

public interface MemberService {
    JwtToken signIn(String username, String password);
}
