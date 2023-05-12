package com.example.study0501.domain;

import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;

@Getter @AllArgsConstructor @Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity @Table(name = "users")
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    private String email;
    private String password;
    private String nickname;
    private String imageUrl;
    private int age;
    private String city;

    @Enumerated(EnumType.STRING)
    private Role role; // GUEST , USER , ADMIN

    @Enumerated(EnumType.STRING)
    private SocialType socialType; // GOOGLE, NAVER, KAKAO
    private String socialId; // 로그인 한 SocialType 식별자 값 (일반 로그인 NULL)

    private String refreshToken;


    // ** 메소드 **

    // Role -> ( User 설정 메소드)
    public void authorizeUser(){
        this.role = Role.USER;
    }
    // 비밀번호 암호화 메소드
    public void passwordEncode(PasswordEncoder passwordEncoder){
        this.password = passwordEncoder.encode(this.password);
    }
    // refreshToken 업데이트
    public void updateRefreshToken(String updateRefreshToken){
        this.refreshToken = updateRefreshToken;
    }

}
