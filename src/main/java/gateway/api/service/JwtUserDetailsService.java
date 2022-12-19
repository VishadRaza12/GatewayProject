package gateway.api.service;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import javax.servlet.http.HttpServletRequest;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gateway.api.bean.UserDTO;
import gateway.api.exception.CustomException;
import gateway.api.model.JWTToken;
import gateway.api.model.Users;
import gateway.api.repository.JWTTokenRepository;
import gateway.api.repository.UserRepository;

@Service
//@CacheConfig(cacheNames = "userJWTcache")
public class JwtUserDetailsService implements UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(JwtUserDetailsService.class);

	ObjectMapper mapper = new ObjectMapper();

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder bcryptEncoder;

	@Autowired
	private JWTTokenRepository jwtTokenRepository;

	@Autowired
	private HttpServletRequest request;

	@Override
	public UserDetails loadUserByUsername(final String empId) throws UsernameNotFoundException {

		logger.info("In JwtUserDetailsService class");
        logger.debug("Method Call : loadUserByUsername(empId="+empId+")");

//		/* Checking Ip For DDOS Protection */
//		String ip = getClientIP();
//		logger.debug("This is ip string: "+ip);

	
		final Users user = userRepository.findByEmpId(empId);
		try {
			logger.debug("This is use object : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user));
		} catch (JsonProcessingException e) {
			logger.error("Exception occurred: "+e.getMessage());
			e.printStackTrace();
		}

		if (user == null) {
			logger.error("The requested user not found.");
			//throw new UsernameNotFoundException("User not found with username: " + userRepository);
			throw new CustomException("The username and/or password are incorrect", HttpStatus.UNAUTHORIZED,
					1001, 2011);
		}

		UserDetails userDetails = null;
		try {
			userDetails = new org.springframework.security.core.userdetails.User(user.getEmpId(), user.getPassword(),getAuthority(user));
			logger.debug("RESPONSE: This is userDetails object: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(userDetails));

		} catch (JsonProcessingException e) {
			logger.error("Exception occurred: "+e.getMessage());
			e.printStackTrace();
		}
		return userDetails;
}

	private Set<SimpleGrantedAuthority> getAuthority(Users user) throws JsonProcessingException {

		logger.info("In JwtUserDetailsService class");
        logger.debug("Method Call : getAuthority(user)");
		logger.debug("REQUEST (Users) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user));

		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRole()));

		});
		logger.debug("RESPONSE: This is SimpleGrantedAuthority object set: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(authorities));
		return authorities;

	}

	public Users save(final UserDTO user) throws JsonProcessingException {

		logger.info("In JwtUserDetailsService class");
        logger.debug("Method Call : save(user)");
		logger.debug("REQUEST (UserDTO) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user));
		
		final Users newUser = new Users();
		newUser.setFirstName(user.getFirstName());
		newUser.setEmpId(user.getEmpId());
		newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
		logger.debug("RESPONSE: This is saved object: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(newUser));
		return userRepository.save(newUser);
	}


	public void saveUserAssignedJWT(final String Token, final String empID, Users userObj) throws JsonProcessingException {

		
		final JWTToken jwtToken = new JWTToken();

		jwtToken.setUserId(userObj);
		jwtToken.setJWTtoken(Token);
		jwtToken.setCreated(new Date());
		logger.debug("RESPONSE: This is saved jwtToken object: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(jwtToken));
		jwtTokenRepository.save(jwtToken);
	}

	// In order to validate in DB so that we can find out application has not
	// Make it Cacheable so that it wont update untill its keys differ SHEREEN
	//@Cacheable(cacheNames = "GetUserAssignedJWTDetails")
	public List<JWTToken> GetUserAssignedJWTDetails(final String empId) throws JsonProcessingException {

		logger.info("In JwtUserDetailsService class");
		logger.debug("Method Call : GetUserAssignedJWTDetails(empId="+empId+")");

		List<JWTToken> Tokenlist = new ArrayList<JWTToken>();
		final Users user = userRepository.findByEmpId(empId);
		logger.debug("This is user : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user));

		Tokenlist = jwtTokenRepository.findByUserId(user);
		logger.debug("RESPONSE: This is returned JWTToken object list: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(Tokenlist));
		return Tokenlist;
	}

	
	public boolean IsJWTTokenAlreadyExistInDB(final String empId, final String jWTTokenString) throws JsonProcessingException {

		logger.info("In JwtUserDetailsService class");
		logger.debug("Method Call : IsJWTTokenAlreadyExistInDB(empId="+empId+",jWTTokenString="+jWTTokenString+")");

		List<JWTToken> Tokenlist = new ArrayList<JWTToken>();
		
			Tokenlist = GetUserAssignedJWTDetails(empId);
		
		logger.debug("This is JWTToken object list: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(Tokenlist));

		Boolean bool= containsToken(Tokenlist, jWTTokenString);
		logger.debug("RESPONSE: This is returned boolean: "+bool);
		return bool;
	}

	public boolean containsToken(final List<JWTToken> list, final String jwtToken) throws JsonProcessingException {

		logger.info("In JwtUserDetailsService class");
		logger.debug("Method Call : containsToken(list,jwtToken="+jwtToken+")");
		logger.debug("REQUEST (List<JWTToken>) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(list));

		Boolean bool= list.stream().anyMatch(o -> o.getJWTtoken().equals(jwtToken));
		logger.debug("RESPONSE: This is returned boolean: "+bool);
		return bool;
	}

	public void signout(String username) throws JsonProcessingException {

		logger.info("In JwtUserDetailsService class");
		logger.debug("Method Call : signout(username="+username+")");
		
		Users userID = userRepository.findByEmpId(username);
		logger.debug("This is user object: "+mapper.writerWithDefaultPrettyPrinter().writeValueAsString(userID));

	
		jwtTokenRepository.deleteByUserId(userID);
		logger.debug("The requested userID has been successfully deleted.");
		
	

	}


}
