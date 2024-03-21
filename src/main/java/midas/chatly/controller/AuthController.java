package midas.chatly.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.dto.request.*;
import midas.chatly.jwt.dto.request.SocialIdRequest;
import midas.chatly.jwt.dto.response.TokenResponse;
import midas.chatly.jwt.service.JwtService;
import midas.chatly.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Slf4j
@RequestMapping("/auth")
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/send-email")
    public ResponseEntity<Object> sendEmail(@RequestBody EmailRequest emailRequest) {
        authService.sendEmail(emailRequest);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);

    }

    @PostMapping("/verify-email")
    public ResponseEntity<Object> verifyEmail(@RequestBody VerifyEmailRequest verifyEmailRequest) {

        authService.verifyEmail(verifyEmailRequest);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/resend-email")
    public ResponseEntity<Object> reSendEmail(@RequestBody EmailRequest emailRequest) {

        authService.sendEmail(emailRequest);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/verify-nickname")
    public ResponseEntity<Object> verifyNickName(@RequestBody NickNameRequest nickNameRequest) {

        authService.verifyNickName(nickNameRequest.getNickName());

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestPart(value = "file", required = false) MultipartFile multipartFile,@Valid @RequestPart(value = "userRequestDto") UserRequest userRequest) throws IOException {

        authService.signup(userRequest.getEmail(), userRequest.getPassword(), multipartFile, userRequest.getNickName());

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Object> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {

        authService.resetPassword(resetPasswordRequest);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/token/logout")
    public ResponseEntity<Object> logout(HttpServletRequest request, @RequestBody SocialIdRequest socialIdRequest) {

        String accessToken = jwtService.extractAccessToken(request).get();
        String refreshToken = jwtService.extractRefreshToken(request).get();
        authService.logout(accessToken, refreshToken, socialIdRequest.getSocialId());
        SecurityContextHolder.clearContext();

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/token/reissue")
    public ResponseEntity<Object> refresh(HttpServletRequest request, HttpServletResponse response, @RequestBody SocialIdRequest socialIdRequest) {

        String refreshToken = jwtService.extractRefreshToken(request).get();
        TokenResponse tokenResponse = authService.validateToken(refreshToken, socialIdRequest.getSocialId());
        jwtService.setTokens(response, tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());

        return new ResponseEntity<>(HttpStatus.OK);
    }
}
