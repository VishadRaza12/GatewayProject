package gateway.api;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.net.URI;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import gateway.api.model.ServiceLog;
import gateway.api.repository.ServiceLogRepository;

@Component
public class LoggingFilter extends OncePerRequestFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(LoggingFilter.class);

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private ServiceLogRepository serviceLogRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
			FilterChain filterChain) throws ServletException, IOException {
		Timestamp startTime = new Timestamp(System.currentTimeMillis());
		ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(httpServletRequest);
		requestWrapper.getParameterMap();
		ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(httpServletResponse);

		filterChain.doFilter(requestWrapper, responseWrapper);

		String requestUrl = requestWrapper.getRequestURL().toString();
		// to omit logging of swagger
		if (!requestUrl.contains("/swagger") && !requestUrl.contains("api-docs")) {

			HttpHeaders requestHeaders = new HttpHeaders();
			Enumeration<String> headerNames = requestWrapper.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				String headerName = (String) headerNames.nextElement();
				requestHeaders.add(headerName, requestWrapper.getHeader(headerName));
			}
			HttpMethod httpMethod = HttpMethod.valueOf(requestWrapper.getMethod());
			Map<String, String[]> requestParams = requestWrapper.getParameterMap();

			String requestBody = new String(requestWrapper.getContentAsByteArray(), "utf-8");
			JsonNode requestJson = objectMapper.readTree(requestBody);

			RequestEntity<JsonNode> requestEntity = new RequestEntity<>(requestJson, requestHeaders, httpMethod,
					URI.create(requestUrl));
			String requestString = requestEntity.getBody().toString();
			LOGGER.debug(requestString, "Logging Http Request");

			@SuppressWarnings("deprecation")
			HttpStatus responseStatus = HttpStatus.valueOf(responseWrapper.getStatusCode());
			HttpHeaders responseHeaders = new HttpHeaders();
			for (String headerName : responseWrapper.getHeaderNames()) {
				responseHeaders.add(headerName, responseWrapper.getHeader(headerName));
			}
			String responseBody = IOUtils.toString(responseWrapper.getContentInputStream(), UTF_8);
			JsonNode responseJson = objectMapper.readTree(responseBody);
			ResponseEntity<JsonNode> responseEntity = new ResponseEntity<>(responseJson, responseHeaders,
					responseStatus);
			String responseString = responseEntity.getBody().toString();
			LOGGER.debug(responseString, "Logging Http Response");

			ServiceLog serviceLog = new ServiceLog();
			serviceLog.setUrl(requestUrl);
			serviceLog.setMethodType(httpMethod.name());
			serviceLog.setRequest(requestString);
			serviceLog.setRequestTime(new Date(startTime.getTime()));
			serviceLog.setResponse(responseString);
			serviceLog.setResponseTime(new Date());
			serviceLogRepository.save(serviceLog);
		}
		responseWrapper.copyBodyToResponse();
	}
}