package midas.chatly.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

@Builder
@Getter
@RequiredArgsConstructor
public class VerifyEmailResonse {

    private final String randomNum;
    private final LocalDateTime createTime;
    private final LocalDateTime expireTime;
}
