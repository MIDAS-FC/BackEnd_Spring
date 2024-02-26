package midas.chatly.service;

import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.ObjectMetadata;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.util.EmailUtil;
import midas.chatly.dto.ResetPasswordRequest;
import midas.chatly.dto.Role;
import midas.chatly.dto.VerifyEmailRequestDto;
import midas.chatly.dto.VerifyEmailResonseDto;
import midas.chatly.entity.User;
import midas.chatly.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;


import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Random;
import java.util.UUID;

import static midas.chatly.oauth.dto.SocialType.CHATLY;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailUtil emailUtil;
    private final AmazonS3Client amazonS3Client;


    @Value("${cloud.aws.s3.bucket}")
    private String bucket;

    @Value("default.profile")
    private String defaultProfile;

    public VerifyEmailResonseDto sendEmail(String email) throws MessagingException {

        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("이미 존재하는 이메일입니다.");
        }

        String randomNum = String.valueOf((new Random().nextInt(90000) + 10000));
        LocalDateTime createTime = LocalDateTime.now();
        LocalDateTime expireTime = LocalDateTime.now().plusMinutes(10);

        emailUtil.sendEmail(email, randomNum);

        VerifyEmailResonseDto verifyEmailResonseDto = VerifyEmailResonseDto.
                builder()
                .randomNum(randomNum)
                .createTime(createTime)
                .expireTime(expireTime)
                .build();

        return verifyEmailResonseDto;

    }

    @Transactional
    public void verifyNickName(String nickName) {

        if (userRepository.existsByNickName(nickName)) {
            throw new RuntimeException("이미 존재하는 닉네임입니다.");
        }
        log.info("{}", nickName);
        User user=User.builder()
                .nickName(nickName)
                .role(Role.USER.getKey())
                .build();

        userRepository.save(user);
    }


    public void verifyEmail(VerifyEmailRequestDto verifyEmailRequestDto) {

        if (userRepository.existsByEmail(verifyEmailRequestDto.getEmail())) {
            throw new RuntimeException("이미 존재하는 이메일입니다.");
        }
        if (!verifyEmailRequestDto.getRandomNum().equals(verifyEmailRequestDto.getInputNum())) {
            throw new RuntimeException("인증번호가 틀렸습니다.");
        }
        if (verifyEmailRequestDto.getSendTime().isAfter(verifyEmailRequestDto.getExpireTime())) {
            throw new RuntimeException("인증번호가 만료되었습니다.");
        }
    }

    @Transactional
    public void signup(String email, String pw, MultipartFile multipartFile, String nickName) throws IOException {
        String socialId = UUID.randomUUID().toString().replace("-", "").substring(0, 13);
        String password = passwordEncoder.encode(pw);
        String url;

        url = createProfileUrl(multipartFile);

        User user = userRepository.findByNickName(nickName).get();
        user.updateAll(email, password, socialId,url,CHATLY.getKey());
        userRepository.save(user);
        userRepository.deleteEverything();
    }

    private String createProfileUrl(MultipartFile multipartFile) throws IOException {
        String url;
        if (multipartFile.isEmpty()) {
            url = defaultProfile;
        } else {
            String fileName = multipartFile.getOriginalFilename();
            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentType(multipartFile.getContentType());
            metadata.setContentLength(multipartFile.getSize());
            amazonS3Client.putObject(bucket, fileName, multipartFile.getInputStream(), metadata);
            url = amazonS3Client.getUrl(bucket, fileName).toString();
        }
        return url;
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest resetPasswordRequest) {

        if (!resetPasswordRequest.getPassword().equals(resetPasswordRequest.getRePassword())) {
            throw new RuntimeException("비밀번호를 재입력 해주세요.");
        }
        if (resetPasswordRequest.getSocialType() != CHATLY.getKey()) {
            throw new RuntimeException("자체 서비스 회원가입 시 만든 비밀번호만 변경 가능합니다.");
        }

        userRepository.findBySocialTypeAndEmail(resetPasswordRequest.getSocialType(),resetPasswordRequest.getEmail())
                .ifPresent(user -> {
                    user.updatePassword(passwordEncoder.encode(resetPasswordRequest.getPassword()));
                    userRepository.save(user);
                });
    }
}