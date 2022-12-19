package gateway.api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import gateway.api.config.CustomHealthIndicator;

@Controller
@CrossOrigin(origins = "*", maxAge = 3600)
@ResponseBody
public class HealthController {

	@Autowired
	private CustomHealthIndicator customHealthIndicator;

	@ResponseBody
	@GetMapping("/health")
	public Health health() {
		return customHealthIndicator.health();
	}

}
