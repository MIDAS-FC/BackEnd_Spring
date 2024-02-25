package midas.chattly.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {

    GUEST("GUEST"), USER("USER");

    private final String key;
}
