package midas.chatly.redis.repository;

import midas.chatly.redis.entity.BlackList;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BlackListRepository extends CrudRepository<BlackList, String> {

    boolean existsByAccessToken(String accessToken);
}