package midas.chatly.redis.repository;


import midas.chatly.redis.entity.EmailAuthentication;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailAuthenticationRepository extends CrudRepository<EmailAuthentication, String> {

    Optional<EmailAuthentication> findById(String id);

    boolean existsById(String id);
}
