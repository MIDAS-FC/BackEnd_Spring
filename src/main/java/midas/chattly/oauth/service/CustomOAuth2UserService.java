package midas.chattly.oauth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chattly.dto.Role;
import midas.chattly.entity.User;
import midas.chattly.oauth.dto.CustomOAuth2User;
import midas.chattly.oauth.dto.OAuthAttributes;
import midas.chattly.oauth.dto.SocialType;
import midas.chattly.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;


import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String NAVER = "naver";
    private static final String KAKAO = "kakao";

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String socialType = getSocialType(registrationId).toString();
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes);
        User createdUser = getUser(extractAttributes, socialType,passwordEncoder); // getUser() 메소드로 User 객체 생성 후 반환

        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(Role.USER.getKey())),
                attributes,
                extractAttributes.getNameAttributeKey(),
                createdUser.getEmail(),
                createdUser.getRole(),
                createdUser.getSocialType(),
                createdUser.getSocialId()
        );
    }

    private SocialType getSocialType(String registrationId) {
        if(NAVER.equals(registrationId)) {
            return SocialType.NAVER;
        }
        if(KAKAO.equals(registrationId)) {
            return SocialType.KAKAO;
        }
        return SocialType.GOOGLE;
    }

    private User getUser(OAuthAttributes attributes, String socialType,PasswordEncoder passwordEncoder) {

        User user = new User();
        Optional<User> users = userRepository.findBySocialId(attributes.getOauth2UserInfo().getId());
        if (users.isEmpty()) {
            user = saveUser(attributes, socialType,passwordEncoder);
        } else {
            user = users.get();
        }
        return user;
    }

    private User saveUser(OAuthAttributes attributes, String socialType,PasswordEncoder passwordEncoder) {

        User createdUser = attributes.toEntity(socialType, attributes.getOauth2UserInfo(),passwordEncoder);
        return userRepository.save(createdUser);
    }
}
