package gateway.api.repository;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.JpaRepository;

import gateway.api.model.JWTToken;
import gateway.api.model.Users;


public interface JWTTokenRepository extends JpaRepository<JWTToken, Long> {

  List<JWTToken> findByJWTtoken(String JWTtoken);

  List<JWTToken> findByUserId(Users userId);

  @Transactional
  String deleteByUserId(Users userID);

}