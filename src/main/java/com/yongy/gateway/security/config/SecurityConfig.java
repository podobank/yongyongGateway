package com.yongy.gateway.security.config;

import com.yongy.gateway.security.filter.JwtAuthenticationFilter;
import com.yongy.gateway.security.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws Exception{
        //jwt 로그인
        http.cors().and()
                .csrf().disable()
                .httpBasic().disable()
                .formLogin().disable()
                .authorizeExchange()
                .pathMatchers("/dotori-user-service/**").permitAll()
                .anyExchange().permitAll()
                .and()
                .addFilterAt(new JwtAuthenticationFilter(jwtTokenProvider), SecurityWebFiltersOrder.AUTHENTICATION)
                .logout().disable();
        return http.build();
    }
}
