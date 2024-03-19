package midas.chatly.redis.repository;

import midas.chatly.redis.entity.RefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken,String> {

    Optional<RefreshToken> findByRefreshToken(String refreshToken);
}
