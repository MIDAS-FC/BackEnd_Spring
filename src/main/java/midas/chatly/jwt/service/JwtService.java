package midas.chatly.jwt.service;


import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.entity.Token;
import midas.chatly.entity.User;
import midas.chatly.error.CustomException;
import midas.chatly.repository.TokenRepository;
import midas.chatly.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Date;
import java.util.Optional;

import static midas.chatly.error.ErrorCode.*;

@Service
@Getter
@Slf4j
public class JwtService {

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String SOCIAL_TYPE = "socialType";
    private static final String SOCIAL_ID = "socialId";
    private static final String BEARER = "Bearer ";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 2;            // 유효기간 2시간
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 14;  // 유효기간 14일

    private String secretKey;
    private String accessHeader;
    private String refreshHeader;
    private final Key key;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    public JwtService(@Value("${jwt.secret-key}") String secretKey,
                      @Value("${jwt.access-header}") String accessHeader,
                      @Value("${jwt.refresh-header}") String refreshHeader,
                      UserRepository userRepository,
                      TokenRepository tokenRepository) {
        this.secretKey = secretKey;
        this.accessHeader = accessHeader;
        this.refreshHeader = refreshHeader;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
    }
    public String generateAccessToken(String socialId) {

        long now = (new Date()).getTime();

        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

        return Jwts.builder()
                .setSubject(ACCESS_TOKEN_SUBJECT)
                .claim(SOCIAL_ID, socialId)
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(String socialId) {

        long now = (new Date()).getTime();

        Date refreshTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

        return  Jwts.builder()
                .setSubject(REFRESH_TOKEN_SUBJECT)
                .claim(SOCIAL_ID, socialId)
                .setExpiration(refreshTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Optional<String> extractEmail(String accessToken) {
        try {
            // 토큰 유효성 검사하는 데에 사용할 알고리즘이 있는 JWT verifier builder 반환
            return Optional.ofNullable(Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody()
                    .get(EMAIL_CLAIM, String.class)
            );
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    public boolean isTokenValid(String token) { //토큰 검증
        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    @Transactional
    public void updateTokens(String socialId, String accessToken, String refreshToken) {
        userRepository.findBySocialId(socialId)
                .ifPresentOrElse(
                        user -> {
                            Token token = user.getToken(); // User로부터 Token을 가져옵니다.
                            if (token != null) {
                                token.updateTokens(accessToken, refreshToken);
                                tokenRepository.saveAndFlush(token); // Token 엔터티에 변경 사항을 저장합니다.
                            } else {
                                throw new CustomException(NO_EXIST_USER_TOKEN); // Token이 없는 경우 예외 처리
                            }
                        },
                        () -> { throw new CustomException(NO_EXIST_USER_SOCIALID); } // User가 없는 경우 예외 처리
                );
    }


    @Transactional
    public void removeRefreshToken(String accessToken) {
        Token tokenInfo = tokenRepository.findByAccessToken(accessToken)
                .orElseThrow(() -> new CustomException(NO_EXIST_USER_ACCESSTOKEN));
        User user = tokenInfo.getUser();

        // First, remove the association between User and Token
        if (user != null) {
            user.setToken(null);
            userRepository.saveAndFlush(user); // Update and flush immediately to avoid foreign key constraint violation
        }

        // Now that User entity is updated, it's safe to delete the Token
        tokenRepository.delete(tokenInfo);
    }

    public String validRefreshToken(String token,String socialId) {

        Optional<Token> refreshToken = tokenRepository.findByRefreshToken(token);

        if (!refreshToken.isPresent()) {
            throw new CustomException(NO_EXIST_USER_REFRESHTOKEN);
        }

        if (!isTokenValid(refreshToken.get().getRefreshToken())) {
            throw new CustomException(NO_VALID_ACCESSTOKEN);
        }


        String newAccessToken = generateAccessToken(socialId);
        refreshToken.get().updateAccessToken(newAccessToken);
        tokenRepository.saveAndFlush(refreshToken.get());

        return newAccessToken;
    }
}

