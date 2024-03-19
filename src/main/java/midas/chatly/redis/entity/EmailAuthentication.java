package midas.chatly.redis.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

@Getter
@AllArgsConstructor
@RedisHash(timeToLive = 600)
public class EmailAuthentication {

    @Id
    @Indexed
    private String id;

    private String randomNum;

    @TimeToLive
    private Long exp;

}
