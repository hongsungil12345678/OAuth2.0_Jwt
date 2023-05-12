package com.example.study0501.jwt;

import com.example.study0501.domain.User;
import com.example.study0501.repository.UserRepository;
import com.example.study0501.service.JwtService;
import com.example.study0501.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {
    private static final String CHECK_URL = "/login";
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final GrantedAuthoritiesMapper grantedAuthoritiesMapper = new NullAuthoritiesMapper();

    // /login 일 경우 다음 필터를 호출
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().startsWith(CHECK_URL)){
            filterChain.doFilter(request, response);
            return;
        }
        // 헤더에 RT가 존재하는 경우 -> AT가 만료된 경우에 해당한다.
        // RT 값과 DB의 RT 값 비교 후 일치하면 AT 재발급
        String extractRefreshToken = jwtService.extractRefreshTokenFromHeader(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);
        if(extractRefreshToken != null){
            checkRefreshTokenAndReIssuedAccessToken(response,extractRefreshToken);
            return;
        }
        // RT 가 없는 경우 -> AT 검증, 인증 처리 로직 구현
        // 객체를 담아서 처리한다.
        if(extractRefreshToken == null){
            checkAccessTokenAndAuthentication(request,response,filterChain);
        }
    }
    /**
     *  [리프레시 토큰으로 유저 정보 찾기 & 액세스 토큰/리프레시 토큰 재발급 메소드]
     *  파라미터로 들어온 헤더에서 추출한 리프레시 토큰으로 DB에서 유저를 찾고, 해당 유저가 있다면
     *  JwtService.createAccessToken()으로 AccessToken 생성,
     *  reIssueRefreshToken()로 리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드 호출
     *  그 후 JwtService.sendAccessTokenAndRefreshToken()으로 응답 헤더에 보내기
     */
    public void checkRefreshTokenAndReIssuedAccessToken(HttpServletResponse response, String refreshToken)throws ServletException, IOException {
        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(user->{
                    String reIssuedRefreshToken = reIssuedRefreshToken(user);
                    jwtService.sendAccessTokenAndRefreshToken(response, jwtService.createAccessToken(user.getRefreshToken()),reIssuedRefreshToken);
                });
    }
    /**
     * [리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드]
     * jwtService.createRefreshToken()으로 리프레시 토큰 재발급 후
     * DB에 재발급한 리프레시 토큰 업데이트 후 Flush
     */
    private String reIssuedRefreshToken(User user){
        String refreshToken = jwtService.createRefreshToken();
        user.updateRefreshToken(refreshToken);
        userRepository.saveAndFlush(user);
        return refreshToken;
    }
    /**
     * [액세스 토큰 체크 & 인증 처리 메소드]
     * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
     * 유효한 토큰이면, 액세스 토큰에서 extractEmail로 Email을 추출한 후 findByEmail()로 해당 이메일을 사용하는 유저 객체 반환
     * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
     * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
     * 그 후 다음 인증 필터로 진행
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request,HttpServletResponse response,FilterChain filterChain)throws IOException, ServletException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService.extractAccessTokenFromHeader(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
                        .ifPresent(email -> userRepository.findByEmail(email)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }

    /**
     * [인증 허가 메소드]
     * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : UserDetails의 User 객체
     *
     * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 파라미터
     * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
     * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
     * 3. Collection < ? extends GrantedAuthority>로,
     * UserDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
     * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
     *
     * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
     * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
     */
    public void saveAuthentication(User user){
        String passsword = user.getPassword();
        log.info("비밀번호 : "+passsword);
        if(passsword == null){
            passsword = PasswordUtil.generateRandomPassword();
            log.info("OAuth2.0 로그인 성공, 비밀번호 생성 완료"+ passsword);
        }
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(passsword)
                .roles(user.getRole().name())
                .build();
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails,null,grantedAuthoritiesMapper.mapAuthorities(userDetails.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
