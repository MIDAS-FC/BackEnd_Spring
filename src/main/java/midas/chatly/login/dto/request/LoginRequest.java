package midas.chatly.login.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class LoginRequest {

    @NotNull
    private String email;

    @NotNull
    private String password;

    @NotNull
    private String socialType;
}
