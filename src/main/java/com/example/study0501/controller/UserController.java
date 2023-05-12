package com.example.study0501.controller;

import com.example.study0501.dto.UserSignUpDto;
import com.example.study0501.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/signup")
    public String singUp(@RequestBody UserSignUpDto userSignUpDto)throws Exception {
        userService.signUp(userSignUpDto);
        return "회원 가입 완료."+"\n Email :  "+userSignUpDto.getEmail()+"\n Nickname : "+userSignUpDto.getNickname();
    }
    @GetMapping("/test")
    public String apiTest(){
        return "test 화면 입니다";
    }
}
