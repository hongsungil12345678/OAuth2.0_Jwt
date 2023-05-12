package com.example.study0501.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class CustomJsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_URL_REQUEST_LOGIN_URL = "/login";
    private static final String HTTP_METHOD = "POST";
    private static final String CONTENT_TYPE = "application/json";
    private static final String USERNAME_KEY = "email";
    private static final String PASSWORD_KEY = "password";
    private static final AntPathRequestMatcher DEFAULT_LOGIN_PATH_LOGIN_REQUEST =
            new AntPathRequestMatcher(DEFAULT_URL_REQUEST_LOGIN_URL,HTTP_METHOD);// "login" + POST 방식에 대해서 매칭
    private final ObjectMapper objectMapper;


    public CustomJsonUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper){
        super(DEFAULT_LOGIN_PATH_LOGIN_REQUEST);// login + post 요청에 대해서 처리하기 위해서 등록
        this.objectMapper = objectMapper;
    }

    /**  인증 처리 흐름 정리 구성이 어떻게 되는지 다시 한 번 확인 할 것
     * 1. UsernamePasswordAuthenticationToken(username, password) -> AuthenticationManger (ProviderManger)
     * 2. AuthenticationManger  -> DaoAuthenticationProvider (AuthenticationProviders)
     * 3. DaoAuthenticationProvider -> UserDetailsService
     * 4. UserDetailsService -> ( UserDetails , password encoder)
     *
     * 결과물 : UsernamePasswordAuthenticationToken (userDetails, Authorities) :
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if(request.getContentType() == null || ! request.getContentType().equals(CONTENT_TYPE)){
            throw new AuthenticationServiceException("CustomJsonUsernamePasswordAuthenticationFilter Class\n attemptAuthentication Method : Content-Type Error!"+ request.getContentType());
        }
        // Json Mapping ( StreamUtils.copyToString )
        String messageBody = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
        Map<String,String> mappingBody = objectMapper.readValue(messageBody, Map.class);

        String email = mappingBody.get(USERNAME_KEY);
        String password = mappingBody.get(PASSWORD_KEY);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);


        return this.getAuthenticationManager().authenticate(authentication);
    }
}
