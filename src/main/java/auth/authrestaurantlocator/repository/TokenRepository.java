package auth.authrestaurantlocator.repository;

import auth.authrestaurantlocator.models.Token;
import auth.authrestaurantlocator.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {


    @Query("""
    select t from Token t inner join fetch User u on t.user.id = u.id\s
    where u.id = :userId and (t.expired = false or t.revoked = false)
            """)
    Optional<List<Token>> findAllValidTokensByUser(Integer userId);

    Optional<Token> findByToken( String token);



}
