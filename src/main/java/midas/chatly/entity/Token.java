package midas.chatly.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
@Builder
@Table(name = "TOKEN")
@AllArgsConstructor
public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "token_id")
    private Long id;

    private String accessToken;

    private String refreshToken;

    @OneToOne
    @JoinColumn(name = "social_id", referencedColumnName = "socialId")
    private User user;
    public void updateAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public void updateTokens(String updateAccessToken, String updateRefreshToken) {
        this.accessToken = updateAccessToken;
        this.refreshToken = updateRefreshToken;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
