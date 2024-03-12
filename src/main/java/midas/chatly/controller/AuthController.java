package midas.chatly.controller;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.dto.request.*;
import midas.chatly.jwt.dto.request.ReIssueRequest;
import midas.chatly.jwt.service.JwtService;
import midas.chatly.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequestMapping("/auth")
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    /*
        Front에서 email(이메일), emailType(회원가입 때의 이메일 보내기인지, 비밀번호 재설정 때의 이메일 보내기인지), socialType(자체 서비스/카카오/네이버/구글) 데이터 받음
     */
    @PostMapping("/send-email")
    public ResponseEntity<Object> sendEmail(@RequestBody EmailRequest emailRequest) throws MessagingException {
        return ResponseEntity.ok(authService.sendEmail(emailRequest));
    }

    /*
        Front에서 email(이메일), emailType(회원가입 때의 이메일 보내기인지, 비밀번호 재설정 때의 이메일 보내기인지), socialType(자체 서비스/카카오/네이버/구글), randomNum(서버에서 발급한 인증번호), inputNum(사용자가 입력한 인증번호),
                 sendTime(사용자가 입력한 인증번호 시간), expireTime(서버에서 발급한 인증번호 만료시간) 데이터 받음
     */
    @PostMapping("/verify-email")
    public ResponseEntity<Object> verifyEmail(@RequestBody VerifyEmailRequest verifyEmailRequest) {

        authService.verifyEmail(verifyEmailRequest);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /*
        Front에서 email(이메일) 데이터 받음
     */
    @PostMapping("/resend-email")
    public ResponseEntity<Object> reSendEmail(@RequestBody EmailRequest emailRequest) throws MessagingException {

        return ResponseEntity.ok(authService.sendEmail(emailRequest));

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
    public ResponseEntity<Object> signup(@RequestPart(value = "file", required = false) MultipartFile multipartFile,@Valid @RequestPart(value = "userRequestDto") UserRequest userRequest) throws IOException {

        authService.signup(userRequest.getEmail(), userRequest.getPassword(), multipartFile, userRequest.getNickName());

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

    @PostMapping("/token/logout")
    public ResponseEntity<Object> logout(@RequestBody HashMap<String,String> accessToken) {

        jwtService.removeRefreshToken(accessToken.get("accessToken"));
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<Object> refresh(HttpServletRequest request, @RequestBody(required = false) ReIssueRequest reIssueRequest) {

        String refreshToken = authService.validateCookie(request);
        String token = authService.validateToken(refreshToken, reIssueRequest.getSocialId());
        Map<String, String> accessToken = new HashMap<>();
        accessToken.put("accessToken", token);

        return ResponseEntity.ok(accessToken);
    }

    @PostMapping("/change-nickname")
    public ResponseEntity<Object> changeNickName(@RequestBody ValidateNickNameRequest validateNickName) {

        authService.changeNickName(validateNickName);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/change-profile")
    public ResponseEntity<Object> changeProfile(@RequestPart(value = "nickName") Map<String,String> nickName, @RequestPart(value = "file") MultipartFile multipartFile) throws IOException {

        String updateProfileUrl = authService.updateProfileUrl(multipartFile, nickName.get("nickName"));
        Map<String, String> profile = new HashMap<>();
        profile.put("url", updateProfileUrl);

        return ResponseEntity.ok(profile);
    }
}
