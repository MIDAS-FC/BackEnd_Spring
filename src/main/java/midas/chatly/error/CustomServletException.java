package midas.chatly.error;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomServletException {

    public static void sendJsonError(HttpServletResponse response, int statusCode, String errorMessage) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setStatus(statusCode);
        String jsonError = String.format("{\"status\": \"%d\", \"message\": \"%s\"}", statusCode, errorMessage);
        response.getWriter().write(jsonError);
    }
}
