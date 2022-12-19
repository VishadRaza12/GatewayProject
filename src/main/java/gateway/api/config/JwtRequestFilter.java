package gateway.api.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import gateway.api.security.services.UserDetailsServiceImpl;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	private static final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);

	ObjectMapper mapper = new ObjectMapper();


	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		logger.info("In JwtRequestFilter class");
		logger.debug("Method Call : doFilterInternal(request,response,filterChain)");
		logger.debug("Request API : " + request.getRequestURI().toString());

		String jwt = parseJwt(request);
		logger.debug("This is the jwt string: " + jwt);

		if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
			String username = jwtUtils.getUserNameFromJwtToken(jwt);
			logger.debug("This is the username string: " + username);

			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			logger.debug("This is userDetails object: "
					+ mapper.writerWithDefaultPrettyPrinter().writeValueAsString(userDetails));

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
					userDetails, null, userDetails.getAuthorities());
			logger.debug("This is UsernamePasswordAuthenticationToken object: "
					+ mapper.writerWithDefaultPrettyPrinter().writeValueAsString(authentication));

			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			SecurityContextHolder.getContext().setAuthentication(authentication);

			filterChain.doFilter(request, response);
			logger.debug("Returning from JwtRequestFilter class");
		} else {
			logger.error("Cannot set user authentication:");
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not authorized to access this resource");
			return;
		}
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		return new AntPathMatcher().match("/authenticate", request.getServletPath())
				|| new AntPathMatcher().match("/api/auth/register", request.getServletPath())
				|| new AntPathMatcher().match("/health", request.getServletPath());
	}

	private String parseJwt(HttpServletRequest request) {

		logger.info("In JwtRequestFilter class");
		logger.debug("Method Call : parseJwt(request)");
		logger.debug("Request API : " + request.getRequestURI().toString());

		String headerAuth = request.getHeader("Authorization");
		logger.debug("This is the headerAuth string: " + headerAuth);

		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			String response = headerAuth.substring(7, headerAuth.length());
			logger.debug("RESPONSE: This is the returned response string: " + response);
			return response;
		}
		logger.debug("RESPONSE: This is the returned response string: null.");
		return null;
	}

}