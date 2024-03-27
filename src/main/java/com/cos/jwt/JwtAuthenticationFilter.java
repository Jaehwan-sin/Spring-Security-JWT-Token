package com.cos.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있다.
// /login 요청해서 username, password 전송하면 (POST)
// UsernamePasswordAuthenticationFilter 동작을 함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticatinoFilter 로그인 시도 중");

        // 1.username,password받아서
        // 2.정상인지로그인시도를해보는거에요.authenticationManager로로그인시도를하면!!
        // PrincipalDetailsService가호출loadUserByUsername()함수실행됨.
        // 3.PrinciapIDetails를세션에담고(권한관리를위해서)
        // 4. JWT  토큰을 만들어서 응답해주면 된다.

        return super.attemptAuthentication(request, response);
    }
}

