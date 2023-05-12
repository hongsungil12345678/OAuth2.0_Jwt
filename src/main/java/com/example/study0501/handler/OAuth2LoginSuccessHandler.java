package com.example.study0501.handler;

import com.example.study0501.domain.Role;
import com.example.study0501.domain.User;
import com.example.study0501.oauth.CustomOAuth2User;
import com.example.study0501.repository.UserRepository;
import com.example.study0501.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2LoginSuccessHandler Class 진입 성공");
        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
            if(oAuth2User.getRole() == Role.GUEST){
                String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());// AT 생성
                response.addHeader(jwtService.getAccessTokenHeader(),"Bearer "+accessToken);
                response.sendRedirect("oauth2/sign-up");

                jwtService.sendAccessTokenAndRefreshToken(response,accessToken,null);
                User findUser = userRepository.findByEmail(oAuth2User.getEmail())
                        .orElseThrow(()-> new IllegalArgumentException("해당 이메일이 존재하지 않습니다 : "+oAuth2User.getEmail()));
                findUser.authorizeUser(); // 인증 실행
            }
            else{
                loginSuccess(response,oAuth2User); // 로그인에 성공한 경우에 해당 -> AT, RT 생성 메소드
            }
        }catch (Exception e) {
            throw e;
        }
    }

    private void loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User){
        String accessToken = jwtService.createAccessToken(oAuth2User.getEmail());
        String refreshToken = jwtService.createRefreshToken();
        response.addHeader(jwtService.getAccessTokenHeader(), "Bearer " + accessToken);
        response.addHeader(jwtService.getRefreshTokenHeader(), "Bearer " + refreshToken);

        jwtService.sendAccessTokenAndRefreshToken(response, accessToken, refreshToken);
        jwtService.updateRefreshToken(oAuth2User.getEmail(), refreshToken);
    }
}
