package midas.chatly.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum ErrorCode {

    EXIST_USER_EMAIL_SOCIALTYPE(HttpStatus.CONFLICT, "해당 socialType의 이메일이 이미 존재합니다."),
    EXIST_USER_NICKNAME(HttpStatus.CONFLICT, "해당 닉네임이 이미 존재합니다."),
    NOT_EXIST_USER_EMAIL_SOCIALTYPE(HttpStatus.NOT_FOUND, "해당 socialType의 이메일이 존재하지 않습니다."),
    NOT_EXIST_USER_EMAIL(HttpStatus.NOT_FOUND, "이메일이 존재하지않습니다."),
    NOT_EXIST_USER_NICKNAME(HttpStatus.NOT_FOUND, "닉네임이 존재하지않습니다."),
    NOT_EXIST_USER_SOCIALID(HttpStatus.NOT_FOUND, "socialId가 존재하지않습니다."),
    NOT_EXIST_REFRESHTOKEN(HttpStatus.NOT_FOUND,"존재하지 않는 Refresh Token입니다."),
    EXIST_REFRESHTOKEN_BLACKLIST(HttpStatus.CONFLICT,"이미 로그아웃한 사용자입니다."),
    NOT_VALID_REFRESHTOKEN(HttpStatus.BAD_REQUEST,"유효하지 않은 Refresh토큰입니다."),
    NOT_EXTRACT_EMAIL(HttpStatus.UNAUTHORIZED, "토큰에서 email을 추출 할 수 없습니다.(잘못된 토큰)"),
    NOT_VALID_ACCESSTOKEN(HttpStatus.UNAUTHORIZED, "Access토큰이 유요하지 않습니다."),
    NOT_EQUAL_JSON(HttpStatus.BAD_REQUEST, "data content-type이 json이 아닙니다."),
    NOT_EXTRACT_ACCESSTOKEN(HttpStatus.UNAUTHORIZED, "토큰에서 AccessToken을 추출 할 수 없습니다.(잘못된 토큰)"),
    WRONG_CERTIFICATION_NUMBER(HttpStatus.BAD_REQUEST,"인증번호가 틀렸습니다."),
    EXPIRE_CERTIFICATION_NUMBER(HttpStatus.BAD_REQUEST,"인증번호가 만료되었습니다."),
    WRONG_PASSWORD(HttpStatus.BAD_REQUEST,"비밀번호를 재입력해주세요"),
    NOT_CHATLY_SOCIALTYPE(HttpStatus.BAD_REQUEST,"자체 서비스 회원가입 시 만든 비밀번호만 변경 가능합니다."),
    SEND_EMAIL_FAIL(HttpStatus.INTERNAL_SERVER_ERROR,"이메일 전송을 실패했습니다."),
    NOT_AUTHENTICATION_INFO(HttpStatus.BAD_REQUEST,"사용자 정보가 없습니다."),
    NOT_EXIST_USER_TOKEN(HttpStatus.NOT_FOUND,"TOKEN DB와 매핑 할 수 없습니다"),
    NOT_EQUAL_EACH_TOKEN_SOCIALID(HttpStatus.BAD_REQUEST, "로그인한 사용자의 Refresh Token이 아닙니다")
    ;

    private final HttpStatus httpStatus;
    private final String message;
}