package com.example.study0501.service;

import com.example.study0501.domain.Role;
import com.example.study0501.domain.User;
import com.example.study0501.dto.UserSignUpDto;
import com.example.study0501.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 자체 로그인 SignUpDto로 받아와서 Entity build
 */
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public void signUp(UserSignUpDto userSignUpDto) throws Exception {
        checkValidation(userSignUpDto);

        User user = User.builder()
                .email(userSignUpDto.getEmail())
                .password(userSignUpDto.getPassword())
                .nickname(userSignUpDto.getNickname())
                .age(userSignUpDto.getAge())
                .city(userSignUpDto.getCity())
                .role(Role.USER)
                .build();
        user.passwordEncode(passwordEncoder); // 비밀번호 암호화

        userRepository.save(user);
    }
    
    // email, nickname 으로 중복회원 검사
    public void checkValidation(UserSignUpDto userSignUpDto) throws Exception {
        if(userRepository.findByEmail(userSignUpDto.getEmail()).isPresent()){
            throw new Exception("이미 존재하는 이메일 입니다. : "+ userSignUpDto.getEmail());
        }
        if(userRepository.findByNickname(userSignUpDto.getNickname()).isPresent()){
            throw new Exception("이미 존재하는 닉네임 입니다. : "+ userSignUpDto.getNickname());
        }
    }
}
