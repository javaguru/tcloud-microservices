package com.jservlet;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.log4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

import javax.servlet.http.HttpServletRequest;

@SpringBootApplication
@EnableDiscoveryClient
@EnableZuulProxy
public class EdgeServiceApplication {

    /**
     * curl http://192.168.137.1:8080/tcloud-service/tclouds
     * curl http://192.168.137.1:8080/tcloud-service/tclouds/search/
     * curl http://192.168.137.1:8080/tcloud-service/tclouds/search/by-name?rn=Test1
     *
     * curl http://192.168.137.1:8080/tcloud-service//tclouds/names
     * curl http://192.168.137.1:8080/tcloud-service/message
     */
	public static void main(String[] args) {
		SpringApplication.run(EdgeServiceApplication.class, args);
	}

	@Bean
	public SimpleFilter simpleFilter() {
		return new SimpleFilter();
	}
}

class SimpleFilter extends ZuulFilter {

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

		logger.info(String.format("%s request to %s", request.getMethod(), request.getRequestURL().toString()));

		return null;
	}

}