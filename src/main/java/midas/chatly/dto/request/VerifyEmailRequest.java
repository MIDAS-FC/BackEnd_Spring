package midas.chatly.dto.request;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

@Builder
@Getter
@RequiredArgsConstructor
public class VerifyEmailRequest {

    private final String email;
    private final String socialType;
    private final String randomNum;
    private final String inputNum;
    private final LocalDateTime sendTime;
    private final LocalDateTime expireTime;
}
