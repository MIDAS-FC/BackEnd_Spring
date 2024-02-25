package midas.chattly.oauth.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SocialType {
    KAKAO("KAKAO"), NAVER("NAVER"), GOOGLE("GOOGLE"), CHATTLY("Chattly");

    private final String key;
}
