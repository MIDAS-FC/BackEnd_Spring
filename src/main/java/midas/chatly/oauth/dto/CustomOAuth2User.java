package midas.chatly.oauth.dto;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuth2User extends DefaultOAuth2User {

    private String email;
    private String role;
    private String socialType;
    private String socialId;
     public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities,
                            Map<String, Object> attributes, String nameAttributeKey,
                            String email, String role, String socialType, String socialId) {
        super(authorities, attributes, nameAttributeKey);
        this.email = email;
        this.role = role;
        this.socialType = socialType;
        this.socialId = socialId;
    }
}
