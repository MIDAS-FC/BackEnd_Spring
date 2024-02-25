package midas.chatly.login.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class LoginRequestDto {

    @NotNull
    private String email;

    @NotNull
    private String password;

    @NotNull
    private String socialType;
}
