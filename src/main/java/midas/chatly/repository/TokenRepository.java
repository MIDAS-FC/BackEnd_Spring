package midas.chatly.repository;


import midas.chatly.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;


public interface TokenRepository extends JpaRepository<Token, Long> {

    boolean existsByRefreshToken(String refreshToken);


}
