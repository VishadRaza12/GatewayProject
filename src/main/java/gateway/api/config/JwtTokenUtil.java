package gateway.api.config;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gateway.api.model.Users;
import gateway.api.model.JWT.JwtConfiguration;
import gateway.api.repository.JwtConfigurationRepository;

@Component
public class JwtTokenUtil implements Serializable {
	private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

	ObjectMapper mapper = new ObjectMapper();

	@Autowired
	JwtConfigurationRepository jwtConfigurationRepository;

	@Autowired
	JwtSecretKey jwtSecretKey;

	private static final long serialVersionUID = -2550185165626007488L;

	private String secret;

	public static long JWT_TOKEN_VALIDITY = 10000;

	public static long JWT_REFRESHTOKEN_VALIDITY;

	public String getSecretKey(JwtConfiguration jwt) throws JsonProcessingException {

		logger.info("In JwtTokenUtil class");
		logger.debug("Method Call : getSecretKey()");

		if(jwt == null) {
			jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();	
		}
		logger.debug("This is JwtConfiguration object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt));

		JWT_TOKEN_VALIDITY = jwt.getJwtvalidity();
		logger.debug("This is the JWT_TOKEN_VALIDITY: "+JWT_TOKEN_VALIDITY);

		JWT_REFRESHTOKEN_VALIDITY = jwt.getJwtRefreshTokenValidity();
		logger.debug("This is the JWT_REFRESHTOKEN_VALIDITY: "+JWT_REFRESHTOKEN_VALIDITY);

		String secret = jwtSecretKey.decrypt(jwt, jwt.getJwtsecretkey(), jwt.getEncryptionsecretkey());
		logger.debug("RESPONSE: This is the returned secret string: "+secret);
		return secret;
	}

	// retrieve username from jwt token
	public String getUsernameFromToken(String token) throws JsonProcessingException {

		logger.info("In JwtUtils class");
	    logger.debug("Method Call : getUsernameFromToken(token="+token+")");

		JwtConfiguration jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();
		logger.debug("This is JwtConfiguration object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt));

		JWT_TOKEN_VALIDITY = jwt.getJwtvalidity();
		logger.debug("This is the JWT_TOKEN_VALIDITY: "+JWT_TOKEN_VALIDITY);

		JWT_REFRESHTOKEN_VALIDITY = jwt.getJwtRefreshTokenValidity();
		logger.debug("This is the JWT_REFRESHTOKEN_VALIDITY: "+JWT_REFRESHTOKEN_VALIDITY);

		String secret = jwtSecretKey.decrypt(null, jwt.getJwtsecretkey(), jwt.getEncryptionsecretkey());
		String s = JWT.require(Algorithm.HMAC512(secret.getBytes()))
				.build()
				.verify(token)
				.getSubject();
		logger.debug("RESPONSE: This is the returned response string: "+s);
		return s;
	}

	// retrieve expiration date from jwt token
	public Date getExpirationDateFromToken(String token) throws JsonProcessingException {

		logger.info("In JwtUtils class");
	    logger.debug("Method Call : getExpirationDateFromToken(token="+token+")");

		Date responseDate= getClaimFromToken(token, Claims::getExpiration);
		logger.debug("RESPONSE: This is the returned response date: "+responseDate);
		return responseDate;
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) throws JsonProcessingException {

		logger.info("In JwtUtils class");
	    logger.debug("Method Call : getClaimFromToken(claimsResolver,token="+token+")");

		final Claims claims = getAllClaimsFromToken(token);
		logger.debug("This is Claims object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(claims));

		return claimsResolver.apply(claims);

	}

	// for retrieveing any information from token we will need the secret key
	private Claims getAllClaimsFromToken(String token) throws JsonProcessingException {

		logger.info("In JwtUtils class");
	    logger.debug("Method Call : getAllClaimsFromToken(token="+token+")");

		secret = getSecretKey(null);
		logger.debug("This is the secret string: "+secret);

		Claims claims= Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
		logger.debug("RESPONSE: This is Claims object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(claims));
		return claims;
	}

	// check if the token has expired
	private Boolean isTokenExpired(String token) throws JsonProcessingException {

		logger.info("In JwtUtils class");
	    logger.debug("Method Call : isTokenExpired(token="+token+")");

		final Date expiration = getExpirationDateFromToken(token);
		logger.debug("This is Date object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(expiration));

		Boolean bool= expiration.before(new Date());
		logger.debug("RESPONSE: This is returned boolean value: " +bool);
		return bool;
	}

	// generate token for user
	public String generateToken(Users user, JwtConfiguration jwt) throws JsonProcessingException {

		logger.info("In JwtUtils class");
		logger.debug("Method Call : generateToken(userDetails)");
		logger.debug("REQUEST (userDetails) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user));

		Map<String, Object> claims = new HashMap<>();
		String response= doGenerateToken(claims, user.getEmpId(), jwt);
		logger.debug("RESPONSE: This is the returned response string: "+response);
		return response;
	}

	private String doGenerateToken(Map<String, Object> claims, String subject, JwtConfiguration jwt) throws JsonProcessingException {

		logger.info("In JwtUtils class");
		logger.debug("Method Call : doGenerateToken(claims,subject="+subject+")");
		logger.debug("REQUEST: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(claims));

		logger.debug("This is JwtConfiguration object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwt));

		JWT_TOKEN_VALIDITY = jwt.getJwtvalidity();
		logger.debug("This is the JWT_TOKEN_VALIDITY: "+JWT_TOKEN_VALIDITY);

		secret = getSecretKey(jwt);
		logger.debug("This is the secret string: "+secret);

		String token = JWT.create()
				.withSubject(subject)
				.withIssuedAt(new Date())
				.withExpiresAt(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
				.sign(Algorithm.HMAC512(secret.getBytes()));

		logger.debug("RESPONSE: This is the returned response string: "+token);
		return token;
	}

	// validate token
	public Boolean validateToken(String token, UserDetails userDetails) throws JsonProcessingException {

		logger.info("In JwtUtils class");
		logger.debug("Method Call : validateToken(userDetails,token="+token+")");
		logger.debug("REQUEST(userDetails): " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(userDetails));

		final String username = getUsernameFromToken(token);
		logger.debug("This is the username string: "+username);

		Boolean bool= (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
		logger.debug("RESPONSE: This is the returned boolean value: "+bool);
		return bool;
	}
}