package gateway.api.controller;


import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import gateway.api.bean.UserDTO;
import gateway.api.bean.UserDetailsWithToken;
import gateway.api.config.JwtTokenUtil;
import gateway.api.exception.CustomException;
import gateway.api.model.Dimension;
import gateway.api.model.Perimeter;
import gateway.api.model.Users;
import gateway.api.model.JWT.JwtConfiguration;
import gateway.api.model.JWT.JwtRequest;
import gateway.api.repository.UserRepository;
import gateway.api.repository.JwtConfigurationRepository;
import gateway.api.service.JwtUserDetailsService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import io.jsonwebtoken.ExpiredJwtException;



@RestController
@CrossOrigin
public class JwtAuthenticationController {
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationController.class);

    ObjectMapper mapper = new ObjectMapper();

    @Autowired
    JwtConfigurationRepository jwtConfigurationRepository;


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;




    Integer userid = null;
    Integer empStatus = null;
    RestTemplate restTemplate = new RestTemplate();

   
    private final Bucket bucket;

   

    @RequestMapping(value = "/api/auth/register", method = RequestMethod.POST)
    public ResponseEntity<?> saveUser(@RequestBody UserDTO user) throws Exception {

        logger.info("In JwtAuthenticationController class");
        logger.debug("Method Call : saveUser(user)");
        logger.debug("REQUEST (UserDTO) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user));

        ResponseEntity<?> responseEntity = ResponseEntity.ok(userDetailsService.save(user));
        logger.debug("CONTROLLER RESPONSE: This is the returned object responseEntity: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(responseEntity));
        return responseEntity;
    }

    @RequestMapping(value = "/signout", method = RequestMethod.GET)
    public String signout(HttpServletRequest request, Authentication authentication) throws Exception {

        logger.info("In JwtAuthenticationController class");
        logger.debug("Method Call : signout(authentication,request)");
        logger.debug("Request API : " + request.getRequestURI().toString());
        logger.debug("REQUEST (Authentication) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(authentication));

        String jwtToken = null;
        String username = null;
        final String requestTokenHeader = request.getHeader("Authorization");
        logger.debug("This is requestTokenHeader string: " + requestTokenHeader);

        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            logger.debug("This is jwtToken string: " + jwtToken);

            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
                logger.debug("This is username string: " + username);

            } catch (IllegalArgumentException e) {
                logger.error("Unable to get the requested JWT token. ");
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                logger.error("The JWT token has expired. ");
                System.out.println("JWT Token has expired");
            }
        } else {
        }
        userDetailsService.signout(username);

        logger.debug("CONTROLLER RESPONSE: The requested user has successfully signed out.");
        return "sign out successfully!";
    }

    // @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
     private Authentication authenticate(String username, String password) throws Exception {

        logger.info("In JwtAuthenticationController class");
        logger.debug("Method Call : authenticate(username=" + username + ",password=" + password + ")");
        final Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            logger.debug("CONTROLLER RESPONSE: The requested user has successfully authenticated.");
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (DisabledException e) {
          logger.error("The requested user is disabled either permanently or temporarily. ");
            throw new CustomException("The user is disabled either permanently or temporarily.",
                    HttpStatus.UNPROCESSABLE_ENTITY, 1001, 2011);
        } catch (BadCredentialsException e) {
            logger.error("The requested username and/or password are incorrect. ");
            throw new CustomException("Invalid Username Or Password", HttpStatus.UNAUTHORIZED,
                    1001, 2011);
        }
        return authentication;
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<UserDetailsWithToken> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest,
                                                                          HttpServletRequest servletRequest) throws Exception {

        logger.info("In JwtAuthenticationController class");
        logger.debug("Method Call : createAuthenticationToken(authenticationRequest,servletRequest)");
        logger.debug("Request API : " + servletRequest.getRequestURI().toString());
        logger.debug("REQUEST (JwtRequest) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(authenticationRequest));


        Users userC;

       
            userC = userRepository.findByEmpId(authenticationRequest.getEmpID());

            if (userC == null) {
                throw new CustomException("Invalid Username Or Password", HttpStatus.UNAUTHORIZED);
            }
    
       
        String fullName = "";
        UserDetailsWithToken UserDetailsWithToken = new UserDetailsWithToken();
       

        final Authentication authentication = authenticate(authenticationRequest.getEmpID(), authenticationRequest.getPswd());

      

        JwtConfiguration jwt = jwtConfigurationRepository.findTopByOrderByIdAsc();
        final String token = jwtTokenUtil.generateToken(userC, jwt);
        logger.debug("This is token string: " + token);

        List<String> roles = authentication.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());
        logger.debug("This is roles string list: " + roles);

        UserDetailsWithToken.setRoles(roles);
        UserDetailsWithToken.setEmpId(authenticationRequest.getEmpID());
        fullName = userC.getTitle();
        logger.debug("This is fullName object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(fullName));

		UserDetailsWithToken = setDetailForUsers(UserDetailsWithToken, userC);

        

        UserDetailsWithToken.setUserId(userid);
        UserDetailsWithToken.setFullUsername(fullName);
        userDetailsService.saveUserAssignedJWT(token,  authenticationRequest.getEmpID(), userC);
        UserDetailsWithToken.setTokenString(token);
        
       
        
        logger.debug("This is UserDetailsWithToken object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(UserDetailsWithToken));
        ResponseEntity<UserDetailsWithToken> responseEntity = ResponseEntity.ok(UserDetailsWithToken);
        logger.debug("CONTROLLER RESPONSE: This is UserDetailsWithToken object responseEntity: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(responseEntity));

        return responseEntity;
    }

    private UserDetailsWithToken setDetailForUsers(UserDetailsWithToken userDetailsWithToken, Users userD) throws JsonProcessingException {
        userid = userD.getId();
        logger.debug("This is userid object: " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(userid));
  userDetailsWithToken.setEmail(userD.getEmail());
        return userDetailsWithToken;
    }

    @PostMapping(value = "/api/v1/perimeter/rectangle")
    public ResponseEntity<Perimeter> rectangle(@RequestBody Dimension dimensions) {
    
        if (bucket.tryConsume(1)) {
            return ResponseEntity.ok(new Perimeter("rectangle",
                    (double) 2 * (dimensions.getLength() + dimensions.getBreadth())));
        }
    
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
    }

    public JwtAuthenticationController() {
        Bandwidth limit = Bandwidth.classic(2, Refill.greedy(2, Duration.ofMinutes(1)));
        bucket = Bucket4j.builder()
                .addLimit(limit)
                .build();
    
    }

}
