package midas.chattly.service;

import com.amazonaws.services.s3.AmazonS3Client;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chattly.dto.Role;
import midas.chattly.dto.VerifyEmailResonseDto;
import midas.chattly.entity.User;
import midas.chattly.repository.UserRepository;
import midas.chattly.util.EmailUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;


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



}
