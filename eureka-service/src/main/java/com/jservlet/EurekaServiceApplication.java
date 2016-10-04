package com.jservlet;

import com.netflix.appinfo.HealthCheckHandler;
import com.netflix.appinfo.InstanceInfo;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.health.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/***
 * EurekaServiceApplication
 *
 * curl -s -H "Accept: application/json" http://user:password@localhost:8761/eureka/apps > test.json
 *
 * Supports dynamic re-configuration!
 * curl -d{} http://user:password@localhost:8761/refresh?access_token=da9dedaf-b604-4573-8e56-27af885a04d2
 * ["eureka.numberRegistrySyncRetries","eureka.environment","eureka.datacenter","eureka.server.waitTimeInMsWhenSyncEmpty"]
 *
 *
 * @Author: Franck Andriano
 *
 */
@EnableEurekaServer
@SpringBootApplication
public class EurekaServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(EurekaServiceApplication.class, args);
	}

    /**
     * Register the new health check handler or active it with spring.cloud.config.discovery.enabled=true!
     *
     * @link see https://github.com/spring-cloud/spring-cloud-netflix/issues/643
     */
    @Configuration
    public class EurekaHealthCheckHandlerConfiguration {

        @Autowired(required = false)
        private HealthAggregator healthAggregator = new OrderedHealthAggregator();

        @Bean
        @ConditionalOnMissingBean
        public EurekaHealthCheckHandler eurekaHealthCheckHandler() {
            return new EurekaHealthCheckHandler(healthAggregator);
        }
    }
}

/**
 *  EurekaHealthCheckHandler, Fix Spring Boot Actuator’s health checks propagated to EurekaServer!
 */
class EurekaHealthCheckHandler implements HealthCheckHandler, ApplicationContextAware, InitializingBean {

    /**
     * Map of new health Status
     * @see org.springframework.boot.actuate.health.Status
     */
    private static final Map<Status, InstanceInfo.InstanceStatus> healthStatuses = new HashMap<Status, InstanceInfo.InstanceStatus>() {{
        put(Status.UNKNOWN, InstanceInfo.InstanceStatus.UNKNOWN);
        put(Status.OUT_OF_SERVICE, InstanceInfo.InstanceStatus.OUT_OF_SERVICE);
        put(Status.DOWN, InstanceInfo.InstanceStatus.DOWN);
        put(Status.UP, InstanceInfo.InstanceStatus.UP);
    }};

    private final CompositeHealthIndicator healthIndicator;

    private ApplicationContext applicationContext;

    public EurekaHealthCheckHandler(HealthAggregator healthAggregator) {
        Assert.notNull(healthAggregator, "HealthAggregator must not be null");
        this.healthIndicator = new CompositeHealthIndicator(healthAggregator);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        final Map<String, HealthIndicator> healthIndicators = applicationContext.getBeansOfType(HealthIndicator.class);
        for (Map.Entry<String, HealthIndicator> entry : healthIndicators.entrySet()) {
            healthIndicator.addHealthIndicator(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public InstanceInfo.InstanceStatus getStatus(InstanceInfo.InstanceStatus instanceStatus) {
        return getHealthStatus();
    }

    protected InstanceInfo.InstanceStatus getHealthStatus() {
        final Status status = healthIndicator.health().getStatus();
        return mapToInstanceStatus(status);
    }

    protected InstanceInfo.InstanceStatus mapToInstanceStatus(Status status) {
        if(!healthStatuses.containsKey(status)) {
            return InstanceInfo.InstanceStatus.UNKNOWN;
        }
        return healthStatuses.get(status);
    }
}