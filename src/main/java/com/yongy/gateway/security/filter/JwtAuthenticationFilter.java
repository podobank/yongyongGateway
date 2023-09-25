package com.yongy.gateway.security.filter;

import com.yongy.gateway.security.provider.JwtTokenProvider;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;


    @PostConstruct
    public void init() {
        log.info("----------------------------INIT_FILTER----------------------------");
    }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain){
        ServerHttpRequest request = exchange.getRequest();
        log.info(request.getPath() + " " + request.getMethod());

        log.info("----------------------------DO_FILTER----------------------------");
        String token = resolveToken(request);

        Authentication authentication = null;
        ServerWebExchange modifiedExchange = null;

        //수정 필요
//        if(token!= null){
//            to
//        }


        if(authentication != null) {
            return chain.filter(modifiedExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        } else {
            return chain.filter(exchange);
        }
    }

    private String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            return bearerToken;
        }
        return null;
    }
}
