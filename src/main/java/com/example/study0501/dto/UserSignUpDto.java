package com.example.study0501.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 *  자체 로그인 회원가입 API에서 사용할 DTO
 */

@Getter
@NoArgsConstructor
public class UserSignUpDto {
    private String email;
    private String password;
    private String nickname;
    private int age;
    private String city;
}
