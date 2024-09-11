package Jwt;

import lombok.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;

@Component
public class JwtGenerator {
    private final Key key;

    // application.yml에서 secret 값 가져와서 key에 저장
    public JwtGenerator (@Value("${jwt.secret}") String secretKey){
        byte[] keyBytes = Base64.Decoder.BASE64.decode(secretKey);
        this.key = Key.hmacShakeyFor(keyBytes);
    }

}
