package ru.antonov.securitytest.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    @Query(value = """
            SELECT t FROM Token t JOIN User u on t.user.id = u.id
            WHERE u.id = :userId and (t.expired = false and t.revoked = false)
            """
    )
    List<Token> findAllValidTokenByUser(Long userId);

    Optional<Token> findByToken(String token);
}
