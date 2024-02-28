package midas.chatly.repository;

import midas.chatly.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;


@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByNickName(String nickname);

    Optional<User> findByRefreshToken(String refreshToken);
    Optional<User> findBySocialTypeAndEmail(String socialType,String email);

    boolean existsByEmailAndSocialType(String email,String socialType);
    Optional<User> findBySocialId(String socialId);

    boolean existsByNickName(String nickName);

    @Transactional
    @Modifying
    @Query("delete from User e where e.email is null ")
    void deleteEverything();
}
