package com.example.study0501.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.study0501.repository.UserRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
@Getter
public class JwtService {
    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationIn;
    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationIn;

    @Value("${jwt.access.header}")
    private String accessTokenHeader;
    @Value("${jwt.access.header}")
    private String refreshTokenHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT= "RefreshToken";

    private static final String CLAIM_EMAIL = "email";
    private static final String AUTH_HEADER= "Bearer ";

    private final UserRepository userRepository;


    // accessToken 생성
    public String createAccessToken(String email){
        Date now = new Date();
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime()+accessTokenExpirationIn))
                .withClaim(CLAIM_EMAIL,email)
                .sign(Algorithm.HMAC512(secretKey));
    }
    // refreshToken 생성 ( refreshToken 은 Subject 를 넣지 않는다) 주의!
    public String createRefreshToken(){
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(now.getTime()+refreshTokenExpirationIn))
                .sign(Algorithm.HMAC512(secretKey));
    }
    // accessToken 헤더 실어서 보내기
    public void sendAccessToken(HttpServletResponse response,String accessToken){
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessTokenHeader,accessToken);
        log.info("sendAccessToken Method 실행 : "+accessToken);
    }
    // accessToken + refreshToken 헤더
    public void sendAccessTokenAndRefreshToken(HttpServletResponse response,String accessToken,String refreshToken){
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(accessTokenHeader,accessToken);
        response.setHeader(refreshTokenHeader,refreshToken);
        log.info("sendAccessTokenAndRefreshToken Method 실행"+"\nAccessToken : "+accessToken+"\nRefreshToken : "+refreshToken);

    }
    
    // 헤더에서 accessToken 추출 : "Bearer " 제거 한 후 반환
    public Optional<String> extractAccessTokenFromHeader(HttpServletRequest request){
        return Optional.ofNullable(request.getHeader(accessTokenHeader))
                .filter(tokenHeader->tokenHeader.startsWith(AUTH_HEADER))
                .map(tokenHeader->tokenHeader.substring(AUTH_HEADER.length()));
    }

    // 헤더에서 refreshToken 추출
    public Optional<String> extractRefreshTokenFromHeader(HttpServletRequest request){
        return Optional.ofNullable(request.getHeader(refreshTokenHeader))
                .filter(tokenHeader->tokenHeader.startsWith(AUTH_HEADER))
                .map(tokenHeader -> tokenHeader.substring(AUTH_HEADER.length()));
    }
    // 검증
    public boolean isTokenValid(String token){
        try {
            JWT.require(Algorithm.HMAC512(secretKey))
                    .build()
                    .verify(token);
            return true;

        }catch (Exception e){
            log.info("유효하지 않은 토큰입니다.  : "+e.getMessage());
            return false;
        }
    }

    // 헤더 설정
    public void setAccessTokenHeader(HttpServletResponse response,String accessToken){
        response.setHeader(accessTokenHeader,accessToken);
    }
    // 헤더 설정

    public void setRefreshTokenHeader(HttpServletResponse response,String refreshToken){
        response.setHeader(refreshTokenHeader,refreshToken);
    }
    // 이메일
    /**
     * AccessToken에서 Email 추출
     * 추출 전에 JWT.require()로 검증기 생성
     * verify로 AceessToken 검증 후
     * 유효하다면 getClaim()으로 이메일 추출
     * 유효하지 않다면 빈 Optional 객체 반환
     */
    public Optional<String> extractEmail(String accessToken){
        try{ // 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey))
                    .build() // 반환된 빌더로 JWT verifier 생성
                    .verify(accessToken) // accessToken을 검증하고 유효하지 않다면 예외 발생
                    .getClaim(CLAIM_EMAIL) // claim(Emial) 가져오기
                    .asString());

        }catch (Exception e){
            log.info("유효하지 않은 토큰입니다. : "+e.getMessage());
            return Optional.empty();
        }
    }
    // 저장 (refreshToken)
    public void updateRefreshToken(String email,String refreshToken){
        userRepository.findByEmail(email)
                .ifPresentOrElse(user-> user.updateRefreshToken(refreshToken),
                        ()->new RuntimeException("해당 이메일이 존재하지 않습니다. Email :"+email+"\n refreshToken : "+refreshToken)
        );
    }

}
