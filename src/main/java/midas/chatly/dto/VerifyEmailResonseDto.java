package midas.chatly.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

@Builder
@Getter
@RequiredArgsConstructor
public class VerifyEmailResonseDto {

    private final String randomNum;
    private final LocalDateTime createTime;
    private final LocalDateTime expireTime;
}
