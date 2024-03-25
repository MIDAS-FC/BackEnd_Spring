package midas.chatly.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class VerifyEmailRequest {

    private String email;
    private String emailType;
    private String inputNum;
    private String socialType;
}
