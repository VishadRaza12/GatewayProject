package gateway.api.config;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gateway.api.model.JWT.JwtConfiguration;
import gateway.api.repository.JwtConfigurationRepository;
import gateway.api.security.services.UserDetailsImpl;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	ObjectMapper mapper = new ObjectMapper();
  
  @Autowired
  JwtConfigurationRepository jwtConfigurationRepository;

	@Autowired
	JwtSecretKey jwtSecretKey;

  private String jwtSecret;

  // @Value("${jwtExpirationMs}")
  // private int jwtExpirationMs;


	private static final long serialVersionUID = -2550185165626007488L;


	public static long JWT_TOKEN_VALIDITY = 10000;
  public static long JWT_REFRESHTOKEN_VALIDITY;

  public String generateJwtToken(UserDetailsImpl userPrincipal) throws JsonProcessingException {

    logger.info("In JwtUtils class");
    logger.debug("Method Call : generateJwtToken(userPrincipal)");
    logger.debug("REQUEST (UserDetailsImpl) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(userPrincipal));

    String s= generateTokenFromUsername(userPrincipal.getUsername());
    logger.debug("RESPONSE: This is the returned string: "+s);
    return s;
  }


  public String getSecretKey() throws JsonProcessingException {

    logger.info("In JwtUtils class");
    logger.debug("Method Call : getSecretKey()");
    
		JwtConfiguration jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();
    logger.debug("This is JwtConfiguration object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt));

		JWT_TOKEN_VALIDITY = jwt.getJwtvalidity();
    logger.debug("This is the JWT_TOKEN_VALIDITY: "+JWT_TOKEN_VALIDITY);

    JWT_REFRESHTOKEN_VALIDITY = jwt.getJwtRefreshTokenValidity();
    logger.debug("This is the JWT_REFRESHTOKEN_VALIDITY: "+JWT_REFRESHTOKEN_VALIDITY);

		String secret = jwtSecretKey.decrypt(null, jwt.getJwtsecretkey(), jwt.getEncryptionsecretkey());
    logger.debug("RESPONSE: This is the returned secret string: "+secret);
		return secret;
	}

  /** vishad **/

  public String generateRefreshTokenFromUsername(String username) throws JsonProcessingException {

    logger.info("In JwtUtils class");
    logger.debug("Method Call : generateRefreshTokenFromUsername(username="+username+")");

    JwtConfiguration jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();
    logger.debug("This is JwtConfiguration object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt));

    JWT_REFRESHTOKEN_VALIDITY = jwt.getJwtRefreshTokenValidity();
    logger.debug("This is the JWT_REFRESHTOKEN_VALIDITY: "+JWT_REFRESHTOKEN_VALIDITY);

    JWT_TOKEN_VALIDITY = jwt.getJwtvalidity();
    logger.debug("This is the JWT_TOKEN_VALIDITY: "+JWT_TOKEN_VALIDITY);

    jwtSecret = getSecretKey();
    logger.debug("This is the jwtSecret string: "+jwtSecret);

    String returnedString= Jwts.builder().setSubject(username).setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + JWT_REFRESHTOKEN_VALIDITY)).signWith(SignatureAlgorithm.HS512,jwtSecret)
        .compact();
    logger.debug("RESPONSE: This is the returnedString: "+returnedString);
    return returnedString;
  }

  public String generateTokenFromUsername(String username) throws JsonProcessingException {

    logger.info("In JwtUtils class");
    logger.debug("Method Call : generateRefreshTokenFromUsername(username="+username+")");

    JwtConfiguration jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();
    logger.debug("This is JwtConfiguration object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt));

    JWT_REFRESHTOKEN_VALIDITY = jwt.getJwtRefreshTokenValidity();
    logger.debug("This is the JWT_REFRESHTOKEN_VALIDITY: "+JWT_REFRESHTOKEN_VALIDITY);

    JWT_TOKEN_VALIDITY = jwt.getJwtvalidity();
    logger.debug("This is the JWT_TOKEN_VALIDITY: "+JWT_TOKEN_VALIDITY);

    jwtSecret = getSecretKey();
    logger.debug("This is the jwtSecret string: "+jwtSecret);

    String token = JWT.create()
            .withSubject(username)
            .withIssuedAt(new Date())
            .withExpiresAt(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
            .sign(Algorithm.HMAC512(jwtSecret.getBytes()));
    logger.debug("RESPONSE: This is the returnedString: "+token);
    return token;
  }

  public String getUserNameFromJwtToken(String token) {

    logger.info("In JwtUtils class");
    logger.debug("Method Call : getUserNameFromJwtToken(token="+token+")");
    String s = JWT.require(Algorithm.HMAC512(jwtSecret.getBytes()))
            .build()
            .verify(token)
            .getSubject();
    logger.debug("RESPONSE: This is the returned string: "+s);
    return s;
  }

  public boolean validateJwtToken(String authToken) throws JsonProcessingException {

    logger.info("In JwtUtils class");
    logger.debug("Method Call : validateJwtToken(authToken="+authToken+")");

    try {
      jwtSecret = getSecretKey();
      logger.debug("This is the jwtSecret string: "+jwtSecret);

      Algorithm algorithm = Algorithm.HMAC512(jwtSecret);
      JWTVerifier verifier = JWT.require(algorithm)
              .build(); //Reusable verifier instance
      DecodedJWT jwt = verifier.verify(authToken);
      logger.debug("RESPONSE: This is the returned boolean value: true");
      return true;
    } catch (JWTVerificationException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    }
    logger.debug("RESPONSE: This is the returned boolean value: false");
    return false;
  }

}
