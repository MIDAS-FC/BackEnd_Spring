package midas.chatly.oauth.handler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.error.CustomException;
import midas.chatly.jwt.service.JwtService;
import midas.chatly.redis.entity.RefreshToken;
import midas.chatly.redis.repository.RefreshTokenRepository;
import midas.chatly.repository.UserRepository;
import midas.chatly.dto.Role;
import midas.chatly.entity.User;
import midas.chatly.oauth.dto.CustomOAuth2User;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static midas.chatly.error.CustomServletException.sendJsonError;
import static midas.chatly.error.ErrorCode.NOT_EXIST_USER_SOCIALID;


@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("OAuth2 Login 성공!");
        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

            String accessToken = jwtService.generateAccessToken(oAuth2User.getSocialId());
            String refreshToken = jwtService.generateRefreshToken(oAuth2User.getSocialId());

            if(oAuth2User.getRole() == Role.GUEST.getKey()) {
                User user = userRepository.findBySocialId(oAuth2User.getSocialId()).orElseThrow(() -> new CustomException(NOT_EXIST_USER_SOCIALID));

                String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/login-success")
                        .queryParam("email",oAuth2User.getEmail())
                        .queryParam("socialId",oAuth2User.getSocialId())
                        .queryParam("accessToken", accessToken)
                        .queryParam("refreshToken", refreshToken)
                        .build()
                        .encode(StandardCharsets.UTF_8)
                        .toUriString();

                response.setHeader("Authorization-Access", "Bearer" + accessToken);
                response.setHeader("Authorization-Refresh", "Bearer" + refreshToken);
                response.setStatus(HttpStatus.OK.value());
                response.sendRedirect(targetUrl);


            } else {
                loginSuccess(response, oAuth2User,accessToken,refreshToken); // 로그인에 성공한 경우 access, refresh 토큰 생성
            }
            Optional<RefreshToken> token = refreshTokenRepository.findByRefreshToken(refreshToken);

            if (token.isEmpty()) {
                refreshTokenRepository.save(new RefreshToken(oAuth2User.getSocialId(), refreshToken));
            } else {
                token.get().updateRefreshToken(refreshToken);
                refreshTokenRepository.save(token.get());
            }
        } catch (CustomException e) {
            sendJsonError(response, e.getErrorCode().getHttpStatus().value(), e.getErrorCode().getMessage());
        }

    }

    private void loginSuccess(HttpServletResponse response, CustomOAuth2User oAuth2User,String accessToken,String refreshToken) throws IOException {

        String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/login-success")
                .queryParam("email",oAuth2User.getEmail())
                .queryParam("socialId",oAuth2User.getSocialId())
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .build()
                .encode(StandardCharsets.UTF_8)
                .toUriString();

        response.setHeader("Authorization-Access", accessToken);
        response.setHeader("Authorization-Refresh", refreshToken);
        response.setStatus(HttpStatus.OK.value());
        response.sendRedirect(targetUrl);


    }
}
