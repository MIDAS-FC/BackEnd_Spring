package midas.chatly.dto.request;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class EmailRequest {

    private final String email;
    private final String emailType;
    private final String socialType;

}
