package midas.chatly.login.handler;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.entity.User;
import midas.chatly.error.CustomException;
import midas.chatly.jwt.service.JwtService;
import midas.chatly.redis.entity.RefreshToken;
import midas.chatly.redis.repository.RefreshTokenRepository;
import midas.chatly.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static midas.chatly.error.ErrorCode.NOT_EXIST_USER_SOCIALID;


@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;


    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        String socialId = extractUsername(authentication);

        User userInfo = userRepository.findBySocialId(socialId)
                .orElseThrow(() -> new CustomException(NOT_EXIST_USER_SOCIALID));
        String email = userInfo.getEmail();

        String accessToken = jwtService.generateAccessToken(socialId);
        String refreshToken = jwtService.generateRefreshToken(socialId);

        Optional<RefreshToken> token = refreshTokenRepository.findByRefreshToken(refreshToken);

        if (token.isEmpty()) {
            refreshTokenRepository.save(new RefreshToken(socialId, refreshToken));
        } else {
            token.get().updateRefreshToken(refreshToken);
            refreshTokenRepository.save(token.get());
        }

        log.info("로그인에 성공하였습니다. 이메일 : {}", email);
        log.info("로그인에 성공하였습니다. AccessToken : {}", accessToken);
        log.info("로그인에 성공하였습니다. RefreshToken : {}", refreshToken);

        response.setHeader("Authorization-Access", "Bearer " + accessToken);
        response.setHeader("Authorization-Refresh", "Bearer " + refreshToken);
        response.setHeader("socialId", socialId);
        response.setStatus(HttpStatus.OK.value());

    }


    private String extractUsername(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }
}
