package com.yongy.gateway.security.filter;


import com.yongy.gateway.security.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;


@Slf4j
@RequiredArgsConstructor
public class AuthorizationHeaderFilter implements WebFilter {

    private final JwtTokenProvider jwtTokenProvider;
    public static final String HEADER_KEY = "Authorization";
    public static final String PREFIX = "Bearer ";


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain){
        ServerHttpRequest request = exchange.getRequest();

        String authToken = resolveToken(request); // 인증토큰

        Authentication authentication = null;
        ServerWebExchange serverWebExchange = null;
        if(StringUtils.hasText(authToken)){ // 토큰이 있는 경우
            if(jwtTokenProvider.validateToken(authToken)){ // 토큰이 유효한 경우
                authentication = jwtTokenProvider.getAuthentication(authToken);

                SecurityContextHolder.getContext().setAuthentication(authentication);

                String id = authentication.getPrincipal().toString();
                log.info(id);
                serverWebExchange = exchange.mutate()
                        .request(builder -> builder.header("id", id))
                        .build();
            }
        }

        if(authentication != null){
            return chain.filter(serverWebExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
        }else{
            return chain.filter(exchange);
        }
    }


    private String resolveToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HEADER_KEY);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(PREFIX)) {
            return bearerToken.substring(PREFIX.length());
        }
        return null;
    }

//    private Mono<Void> handleUnAuthorized(ServerWebExchange exchange){
//        ServerHttpResponse response = exchange.getResponse();
//        response.setStatusCode(HttpStatus.UNAUTHORIZED);
//        return response.setComplete();
//    }


//    public void handleUnAuthorized(ServerHttpResponse response, String errorMessage) {
//        response.setStatusCode(HttpStatus.UNAUTHORIZED);
//        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
//
//        ErrorResponse errorResponse = new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), errorMessage);
//
//        try {
//            String json = new ObjectMapper().writeValueAsString(errorResponse);
//            PrintWriter writer = response.bufferFactory().wrap(response.getRawOutputStream());
//            writer.write(json);
//            writer.flush();
//        } catch (IOException e) {
//            log.error("Error writing JSON response: " + e.getMessage());
//        }
//    }

//    public void generalJwtExceptionHandler(ServerHttpResponse response, ErrorType error) {
//        response.setStatusCode(HttpStatusCode.valueOf(error.getCode()));
//        response.getHeaders().setContentType(MediaType.valueOf("application/json"));
//
//        MegResDto dto = new MegResDto(error.getCode(), error.getMessage());
//
//        try {
//            String json = new ObjectMapper().writeValueAsString(dto);
//            response.getWriter().write(json);
//        } catch (Exception e) {
//            log.error(e.getMessage());
//        }
//    }


}
