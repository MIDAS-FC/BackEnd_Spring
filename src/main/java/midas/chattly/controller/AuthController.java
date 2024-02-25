package midas.chattly.controller;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chattly.dto.ResetPasswordRequest;
import midas.chattly.dto.VerifyEmailRequestDto;
import midas.chattly.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/send-email")
    public ResponseEntity<Object> sendEmail(@RequestBody HashMap<String, String> email) throws MessagingException {
        return ResponseEntity.ok(authService.sendEmail(email.get("email")));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<Object> verifyEmail(@RequestBody VerifyEmailRequestDto verifyEmailRequestDto) {

        authService.verifyEmail(verifyEmailRequestDto);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/resend-email")
    public ResponseEntity<Object> reSendEmail(@RequestBody HashMap<String, String> email) throws MessagingException {

        return ResponseEntity.ok(authService.sendEmail(email.get("email")));

    }

    @PostMapping("/verify-nickname")
    public ResponseEntity<Object> verifyNickName(@RequestBody HashMap<String, String> nickName) {

        authService.verifyNickName(nickName.get("nickName"));

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestPart(value = "file", required = false) MultipartFile multipartFile,@Valid @RequestPart(value = "userRequestDto") UserRequestDto userRequestDto) throws IOException {

        authService.signup(userRequestDto.getEmail(), userRequestDto.getPassword(), multipartFile, userRequestDto.getNickName());

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Object> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {

        authService.resetPassword(resetPasswordRequest);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
