package org.example.oauthsession.repository;

import org.example.oauthsession.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity,Long> {

    UserEntity findByUsername(String username);
}
