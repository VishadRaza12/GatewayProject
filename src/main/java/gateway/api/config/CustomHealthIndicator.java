package gateway.api.config;

import org.springframework.boot.actuate.health.AbstractHealthIndicator;
import org.springframework.stereotype.Component;


@Component
public class CustomHealthIndicator extends AbstractHealthIndicator {




@Override
protected void doHealthCheck(org.springframework.boot.actuate.health.Health.Builder builder) throws Exception {
    // TODO Auto-generated method stub
    
    builder
    .up()
    .withDetail("details", "My custom health indicator");

}
}
