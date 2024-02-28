package midas.chatly.oauth.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SocialType {
    KAKAO("KAKAO"), NAVER("NAVER"), GOOGLE("GOOGLE"), CHATLY("CHATLY");

    private final String key;
}
