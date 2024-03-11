package midas.chatly.login.handler;


import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.entity.Token;
import midas.chatly.entity.User;
import midas.chatly.error.CustomException;
import midas.chatly.jwt.service.JwtService;
import midas.chatly.repository.TokenRepository;
import midas.chatly.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.transaction.annotation.Transactional;

import static midas.chatly.error.ErrorCode.NO_EXIST_USER_SOCIALID;


@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;


    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        String socialId = extractUsername(authentication);

        User userInfo = userRepository.findBySocialId(socialId)
                .orElseThrow(() -> new CustomException(NO_EXIST_USER_SOCIALID));
        String email = userInfo.getEmail();

        String accessToken = jwtService.generateAccessToken(socialId);
        String refreshToken = jwtService.generateRefreshToken(socialId);

        updateToken(userInfo, accessToken, refreshToken);

        log.info("로그인에 성공하였습니다. 이메일 : {}", email);
        log.info("로그인에 성공하였습니다. AccessToken : {}", accessToken);

        response.setHeader("Authorization-Access", accessToken);
        response.addCookie(createCookie("Authorization-Refresh", refreshToken));
        response.setStatus(HttpStatus.OK.value());

    }
    @Transactional
    public void updateToken(User userInfo, String accessToken, String refreshToken) {
        log.info("Updating token for user: {}", userInfo.getEmail());

        Token token = userInfo.getToken();
        if (token == null) {
            token = new Token();
            userInfo.assignToken(token);
        }

        token.updateTokens(accessToken, refreshToken);

        tokenRepository.saveAndFlush(token);

        userRepository.saveAndFlush(userInfo);
    }


    private String extractUsername(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(1000 * 60 * 60 * 24 * 14);
        cookie.setHttpOnly(true);

        return cookie;
    }
}
