package midas.chatly.jwt.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ReIssueRequest {

    private String email;
    private String socialType;
    private String socialId;
    private String refreshToken;
}
