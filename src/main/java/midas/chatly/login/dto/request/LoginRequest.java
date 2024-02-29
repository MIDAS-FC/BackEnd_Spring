package midas.chatly.login.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

    @NotNull
    private String email;

    @NotNull
    private String password;

    @NotNull
    private String socialType;
}
