package midas.chatly.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ResetPasswordRequest {

    @Email
    @NotNull
    private final String email;

    @NotNull
    private final String socialType;

    @NotNull
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&]).{10,15}$",
            message = "비밀번호는 문자, 숫자, 특수문자를 포함하여 10자리 이상 15자리 이하이어야 합니다.")
    private final String password;

    @NotNull
    private final String rePassword;
}
