package com.example.study0501.oauth;

import java.util.Map;

// 소셜 타입별로 유저 정보를 가지는 추상 클래스
// 각 클래스들은 추상 클래스를 상속받아 각 타입 별로 클래스 정보 구현
public abstract class OAuth2UserInfo {
    protected Map<String,Object> attributes;
    public OAuth2UserInfo(Map<String,Object> attributes){
        this.attributes = attributes;
    }
    public abstract String getId();
    public abstract String getNickname();
    public abstract String getImageUrl();
}
