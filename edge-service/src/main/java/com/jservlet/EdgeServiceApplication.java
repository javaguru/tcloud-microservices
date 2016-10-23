package com.jservlet;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

import javax.servlet.http.HttpServletRequest;


/**
 *  Proxy Server
 *
 *  @author Franck Andriano 2016
 */
@EnableResourceServer // Spring Boot 1.3, security.oauth2 in config!
@EnableZuulProxy
@SpringBootApplication
public class EdgeServiceApplication {

    /**
     * curl http://localhost:8080/tcloud-service/tclouds
     * curl http://localhost:8080/tcloud-service/tclouds/search/
     * curl http://localhost:8080/tcloud-service/tclouds/search/by-name?rn=Test1
     *
     * curl http://localhost:8080/tcloud-service/tclouds/names
     * curl http://localhost:8080/tcloud-service/message
     */
	public static void main(String[] args) {
		SpringApplication.run(EdgeServiceApplication.class, args);
	}

	@Bean
	public SsoFilter simpleFilter() {
		return new SsoFilter();
	}

}


class SsoFilter extends ZuulFilter {

	private Logger logger = Logger.getLogger(getClass());

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 1;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public Object run() {
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();

        // Authorization Bearer token!
        logger.info("Authorization: "+request.getHeader("Authorization"));
        logger.info(String.format("%s request to %s authenticated user %s",
                request.getMethod(),
                request.getRequestURL().toString(),
                request.getUserPrincipal().getName()));

		return null;
	}

}