package com.example.study0501.dto;

import com.example.study0501.domain.Role;
import com.example.study0501.domain.SocialType;
import com.example.study0501.domain.User;
import com.example.study0501.oauth.GoogleOAuth2UserInfo;
import com.example.study0501.oauth.KakaoOAuth2UserInfo;
import com.example.study0501.oauth.NaverOAuth2UserInfo;
import com.example.study0501.oauth.OAuth2UserInfo;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.parameters.P;

import java.util.Map;
import java.util.UUID;

@Getter
public class OAuthAttributesDto {
    private String nameAttributeKey; // 로그인 진행시 키가 되는 필드 값(PK)
    private OAuth2UserInfo oAuth2UserInfo;

    @Builder
    public OAuthAttributesDto(String nameAttributeKey, OAuth2UserInfo oAuth2UserInfo){
        this.nameAttributeKey = nameAttributeKey;
        this.oAuth2UserInfo = oAuth2UserInfo;
    }

    public static OAuthAttributesDto of(SocialType socialType, String userNameAttribute, Map<String,Object> attributes){

        if(socialType == SocialType.KAKAO){
            return ofKakao(userNameAttribute, attributes);
        }
        if(socialType == SocialType.NAVER) {
            return ofNaver(userNameAttribute,attributes);
        }
        else{
            return ofGoogle(userNameAttribute, attributes);
        }
    }
    public static OAuthAttributesDto ofKakao(String userNameAttribute, Map<String,Object> attributes){
        return OAuthAttributesDto.builder()
                .nameAttributeKey(userNameAttribute)
                .oAuth2UserInfo(new KakaoOAuth2UserInfo(attributes))
                .build();
    }
    public static OAuthAttributesDto ofNaver(String userNameAttribute, Map<String,Object> attributes){
        return OAuthAttributesDto.builder()
                .nameAttributeKey(userNameAttribute)
                .oAuth2UserInfo(new NaverOAuth2UserInfo(attributes))
                .build();
    }
    public static OAuthAttributesDto ofGoogle(String userNameAttribute, Map<String,Object> attributes){
        return OAuthAttributesDto.builder()
                .nameAttributeKey(userNameAttribute)
                .oAuth2UserInfo(new GoogleOAuth2UserInfo(attributes))
                .build();
    }
    /**
     * of메소드로 OAuthAttributes 객체가 생성되어, 유저 정보들이 담긴 OAuth2UserInfo가 소셜 타입별로 주입된 상태
     * OAuth2UserInfo에서 socialId(식별값), nickname, imageUrl을 가져와서 build
     * email에는 UUID로 중복 없는 랜덤 값 생성
     * role은 GUEST로 설정
     */

    public User toEntity(SocialType socialType,OAuth2UserInfo oAuth2UserInfo){
        return User.builder()
                .socialType(socialType)
                .socialId(oAuth2UserInfo.getId())
                .email(UUID.randomUUID() + "@socialUser.com")
                .nickname(oAuth2UserInfo.getNickname())
                .imageUrl(oAuth2UserInfo.getImageUrl())
                .role(Role.GUEST)
                .build();
    }

}
