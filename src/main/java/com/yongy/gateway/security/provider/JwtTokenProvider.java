package com.yongy.gateway.security.provider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import io.jsonwebtoken.security.Keys;

import java.util.Collections;
import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {


    @Value("${jwt.secret.key}")
    private String salt;

    private Key secretKey;

    @PostConstruct
    protected void init(){
        secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
    }


    //토큰 검증
    public boolean validateToken(String token){
        try{
            // Bearer 검증
            if(!token.substring(0, "Bearer ".length()).equalsIgnoreCase("Bearer ")){
                return false;
            }else{
                token = token.split(" ")[1].trim();
            }
            // setSigningKey(secretKey) : secretKey가 토큰을 생성할 때 사용된 비밀 키와 일치해야함
            // parseClaimsJws(token) : 실제로 JWT 토큰을 파싱하고 클레임을 추출하는 부분이다.
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        }catch(Exception e){
            //
            return false;
        }
    }
    //수정 필요
//    public Authentication getAuthentication(String authId){
//        return new UsernamePasswordAuthenticationToken(user, "", Collections.singleton(new SimpleGrantedAuthority(user.getRole().name())));
//    }


}
