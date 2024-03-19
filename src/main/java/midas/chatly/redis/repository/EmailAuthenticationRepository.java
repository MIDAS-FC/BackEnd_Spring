package midas.chatly.redis.repository;


import midas.chatly.redis.entity.EmailAuthentication;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface EmailAuthenticationRepository extends CrudRepository<EmailAuthentication, String> {

    Optional<EmailAuthentication> findById(String id);

    boolean existsById(String id);
}
