package midas.chatly.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserRequestDto {

    @Email
    @NotNull
    private String email;

    @NotNull
    private String nickName;

    @NotNull
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&]).{10,15}$",
            message = "비밀번호는 문자, 숫자, 특수문자를 포함하여 10자리 이상 15자리 이하이어야 합니다.")
    private String password;


}
