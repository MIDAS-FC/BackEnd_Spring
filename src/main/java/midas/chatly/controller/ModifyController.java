package midas.chatly.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.dto.request.NickNameRequest;
import midas.chatly.dto.request.ResetPasswordRequest;
import midas.chatly.dto.request.ValidateNickNameRequest;
import midas.chatly.dto.response.ModifyAttributeResponse;
import midas.chatly.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class ModifyController {

    private final AuthService authService;

    @PostMapping("/auth/reset-password")
    public ResponseEntity<Object> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {

        authService.resetPassword(resetPasswordRequest);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/change-nickname")
    public ResponseEntity<Object> changeNickName(@RequestBody ValidateNickNameRequest validateNickNameRequest) {

        authService.changeNickName(validateNickNameRequest);

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/change-profile")
    public ResponseEntity<Object> changeProfile(@RequestPart(value = "nickName") NickNameRequest nickNameRequest, @RequestPart(value = "file") MultipartFile multipartFile) throws IOException {

        String updateProfileUrl = authService.updateProfileUrl(multipartFile, nickNameRequest.getNickName());
        Map<String, String> profile = new HashMap<>();
        profile.put("url", updateProfileUrl);

        return ResponseEntity.ok(profile);
    }

    @GetMapping("/profile")
    public ResponseEntity<ModifyAttributeResponse> getEmailNickName(@RequestParam String socialId) {

        ModifyAttributeResponse emailNickName = authService.getEmailNickName(socialId);

        return ResponseEntity.ok(emailNickName);
    }
}
