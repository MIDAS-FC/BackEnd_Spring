package midas.chatly.dto.request;

import lombok.*;

import java.time.LocalDateTime;

@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class VerifyEmailRequest {

    private String email;
    private String emailType;
    private String socialType;
    private String randomNum;
    private String inputNum;
    private LocalDateTime sendTime;
    private LocalDateTime expireTime;
}
