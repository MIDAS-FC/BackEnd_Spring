package midas.chatly.controller;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.service.AuthService;
import midas.chatly.dto.ResetPasswordRequest;
import midas.chatly.dto.UserRequestDto;
import midas.chatly.dto.VerifyEmailRequestDto;
import midas.chatly.login.dto.LoginRequestDto;
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

    /*
        Front에서 email(이메일) 데이터 받음
     */
    @PostMapping("/send-email")
    public ResponseEntity<Object> sendEmail(@RequestBody HashMap<String, String> email) throws MessagingException {
        return ResponseEntity.ok(authService.sendEmail(email.get("email")));
    }

    /*
        Front에서 email(이메일), randomNum(서버에서 발급한 인증번호), inputNum(사용자가 입력한 인증번호),
                 sendTime(사용자가 입력한 인증번호 시간), expireTime(서버에서 발급한 인증번호 만료시간) 데이터 받음
     */
    @PostMapping("/verify-email")
    public ResponseEntity<Object> verifyEmail(@RequestBody VerifyEmailRequestDto verifyEmailRequestDto) {

        authService.verifyEmail(verifyEmailRequestDto);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /*
        Front에서 email(이메일) 데이터 받음
     */
    @PostMapping("/resend-email")
    public ResponseEntity<Object> reSendEmail(@RequestBody HashMap<String, String> email) throws MessagingException {

        return ResponseEntity.ok(authService.sendEmail(email.get("email")));

    }

    /*
        Front에서 nickName(닉네임) 데이터 받음
     */
    @PostMapping("/verify-nickname")
    public ResponseEntity<Object> verifyNickName(@RequestBody HashMap<String, String> nickName) {

        authService.verifyNickName(nickName.get("nickName"));

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /*
        Front에서 form-data형식으로 데이터 받음

        ex) key=file, value=이미지 파일

            key=userRequestDto, value=    {

                                            "email":"*****@naver.com"
                                            "password":"******"
                                            "nickName":"******"
                                           }
     */
    @PostMapping("/signup")
    public ResponseEntity<Object> signup(@RequestPart(value = "file", required = false) MultipartFile multipartFile,@Valid @RequestPart(value = "userRequestDto") UserRequestDto userRequestDto) throws IOException {

        authService.signup(userRequestDto.getEmail(), userRequestDto.getPassword(), multipartFile, userRequestDto.getNickName());

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /*
        이미 로그인된 상태이기에 자체 서비스 회원가입해서 만든 계정만 가능
        Front에서 email(이메일), socialType(로그인 타입), password(변경 할 비밀번호), rePassword(변경 할 비밀번호 재입력) 데이터 받음
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Object> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {

        authService.resetPassword(resetPasswordRequest);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /*
         Front에서 email(이메일), password(변경 할 비밀번호), socialType(로그인 타입) 데이터 받음
    */
    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginRequestDto loginRequestDto) {

        log.info("email:{}",loginRequestDto.getEmail());

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
