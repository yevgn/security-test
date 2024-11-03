package ru.antonov.securitytest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.antonov.securitytest.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}
