package com.jservlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.hystrix.dashboard.EnableHystrixDashboard;

/**
 * HystrixDashboard Server
 *
 * http://localhost:8081/hystrix.html
 *
 * Enter by example :
 * http://localhost:8010/hystrix.stream?access_token=9eef7d81-253b-4d06-9ba0-61023bcb598d
 *
 * @author Franck Andriano 2016
 */
@EnableDiscoveryClient
@EnableHystrixDashboard
@SpringBootApplication
public class HystrixDashboardApplication {

    public static void main(String[] args) {
        SpringApplication.run(HystrixDashboardApplication.class, args);
    }
}
