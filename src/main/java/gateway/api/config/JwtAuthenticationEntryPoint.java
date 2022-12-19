package gateway.api.config;


import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.fasterxml.jackson.core.JsonProcessingException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);
  ObjectMapper mapper = new ObjectMapper();

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
      throws IOException, ServletException {

    logger.info("In JwtAuthenticationEntryPoint class");
    logger.debug("Method Call : commence(request,response,authException)");
    logger.debug("Request API : " + request.getRequestURI().toString());
    logger.debug("REQUEST (AuthenticationException) : " + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(authException));

    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    final Map<String, Object> body = new HashMap<>();
    body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
    body.put("error", "Unauthorized");
    body.put("message", authException.getMessage());
    body.put("path", request.getServletPath());

    final ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(response.getOutputStream(), body);


	}
}