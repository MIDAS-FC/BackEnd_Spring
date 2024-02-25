package midas.chattly.controller;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chattly.dto.VerifyEmailRequestDto;
import midas.chattly.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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


}
