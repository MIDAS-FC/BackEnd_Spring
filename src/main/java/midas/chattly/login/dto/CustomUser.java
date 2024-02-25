package midas.chattly.login.dto;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class CustomUser extends User {

    private final String socialType;

    public CustomUser(String username, String password, Collection<? extends GrantedAuthority> authorities, String socialType) {
        super(username, password, authorities);
        this.socialType = socialType;
    }
}
