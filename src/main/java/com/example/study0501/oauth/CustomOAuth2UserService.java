package com.example.study0501.oauth;

import com.example.study0501.domain.SocialType;
import com.example.study0501.domain.User;
import com.example.study0501.dto.OAuthAttributesDto;
import com.example.study0501.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest,OAuth2User>{

    private final UserRepository userRepository;

    private static final String NAVER = "naver";
    private static final String KAKAO = "kakao";
    private static final String GOOGLE = "google";

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest,OAuth2User> delegate = new DefaultOAuth2UserService();
        // 객체 유저정보
        OAuth2User oAuth2User = delegate.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        // socialType 에 따른 유저 정보를 통한 객체 생성
        OAuthAttributesDto extractAttributes = OAuthAttributesDto.of(socialType, userNameAttributeName, attributes);

        User createdUser = getUser(extractAttributes,socialType);
        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(createdUser.getRole().getKey())),
                attributes,userNameAttributeName, createdUser.getEmail(),createdUser.getRole()
        );
    }
    private SocialType getSocialType(String registrationId){
        if (registrationId.equals(NAVER)) {
            return SocialType.NAVER;
        }
        if(registrationId.equals(KAKAO)){
            return SocialType.KAKAO;
        }
        return SocialType.GOOGLE;
    }

    private User getUser(OAuthAttributesDto attributes, SocialType socialType){
        User findUser = userRepository.findBySocialTypeAndSocialId(socialType,attributes.getOAuth2UserInfo().getId())
                .orElse(null);
        if(findUser == null){
            return saveUser(attributes,socialType);
        }
        return findUser;
    }
    private User saveUser(OAuthAttributesDto attributes,SocialType socialType){
        User createdUser = attributes.toEntity(socialType,attributes.getOAuth2UserInfo());
        return userRepository.save(createdUser);
    }
}
