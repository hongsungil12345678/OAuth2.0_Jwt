package com.example.study0501.oauth;

import java.util.Map;

// 추후 중복코드 extract 따로 빼서 구현 해보기
public class KakaoOAuth2UserInfo extends OAuth2UserInfo{
    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getNickname() {// kakao_account -> profile(nickname)
        Map<String,Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String,Object> profile = (Map<String, Object>) account.get("profile");

        if(account == null || profile == null){
            return null;
        }
        return (String)profile.get("nickname");
    }

    @Override
    public String getImageUrl() {
        Map<String,Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String,Object> profile = (Map<String, Object>) account.get("profile");

        if(account == null || profile == null){
            return null;
        }
        return (String) profile.get("thumbnail_image_url");
    }
}
