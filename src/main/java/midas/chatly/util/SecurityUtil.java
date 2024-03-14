package midas.chatly.util;

import midas.chatly.error.CustomException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static midas.chatly.error.ErrorCode.NOT_AUTHENTICATION_INFO;

public class SecurityUtil {

    private SecurityUtil() {
    }

     public static Long getCurrentUserId() {

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new CustomException(NOT_AUTHENTICATION_INFO);
        }

        return Long.parseLong(authentication.getName());
    }
}
