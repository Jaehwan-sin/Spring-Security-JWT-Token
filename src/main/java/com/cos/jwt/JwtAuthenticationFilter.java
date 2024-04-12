package com.cos.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;  
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor; 
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException; 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse; 
import java.io.IOException;
import java.sql.Date;

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
        try {
            ObjectMapper om = new ObjectMapper(); // JSON 데이터를 파싱한다.
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            // 임의의 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            System.out.println("authenticationToken.getname = " + authenticationToken.getName());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 아래로 진행이 되면 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            principalDetails.getUser().getUsername();
            System.out.println("principalDetails.getUser().getUsername() 로그인이 완료됐다. = " + principalDetails.getUser().getUsername());

            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨.
            //  리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거다.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리때문에 session에 넣어준다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 = 인증이 완료되었다. ");

        // JWT 토큰 만들기
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니고 Hash 암호방식
        String JWTtoken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10))) // 토큰 유지시간 10분으로 지정
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + JWTtoken);
    }
}

