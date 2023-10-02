package com.yongy.gateway.security.provider;

import com.yongy.gateway.security.enums.Role;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtTokenProvider {


    @Value("${jwt.secret.key}")
    private String salt;

    private Key secretKey;

    @PostConstruct
    protected void init(){
        secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
    }

    public Claims getClaims(String token){
        Claims claims;
        try{
            claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        }catch (ExpiredJwtException e) {
            log.info("만료된 토큰");
            throw new BadCredentialsException("만료된 토큰", e);
        } catch (MalformedJwtException e) {
            log.info("유효하지 않은 구성의 토큰");
            throw new BadCredentialsException("유효하지 않은 구성의 토큰", e);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 형식이나 구성의 토큰");
            throw new BadCredentialsException("지원되지 않는 형식이나 구성의 토큰", e);
        } catch (IllegalArgumentException e) {
            log.info("잘못된 입력값");
            throw new BadCredentialsException("잘못된 입력값", e);
        }
        return claims;
    }

    //토큰 검증
    public boolean validateToken(String token){
        try{
            Claims claims = this.getClaims(token);
            return !claims.getExpiration().before(new Date());
        }catch(JwtException | IllegalArgumentException e){
            return false;
        }
    }
    public String getUserIdFromToken(String token){
        return this.getClaims(token).getSubject();
    }

    public Authentication getAuthentication(String token){
        Claims claims = this.getClaims(token);
        return new UsernamePasswordAuthenticationToken(getUserIdFromToken(token), "", Collections.singleton(new SimpleGrantedAuthority(claims.get("role").toString())));
    }



}
