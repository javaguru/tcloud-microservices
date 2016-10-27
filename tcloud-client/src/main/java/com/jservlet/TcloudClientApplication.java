package com.jservlet;

import com.google.common.collect.ImmutableMap;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixProperty;
import feign.RequestInterceptor;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.cloud.security.oauth2.client.feign.OAuth2FeignRequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.hateoas.Resources;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/*import org.springframework.cloud.stream.annotation.EnableBinding;
import org.springframework.cloud.stream.annotation.Output;
import org.springframework.integration.annotation.Gateway;
import org.springframework.integration.annotation.IntegrationComponentScan;
import org.springframework.integration.annotation.MessagingGateway;
import org.springframework.messaging.MessageChannel;*/

/**
 * Tcloud Client
 *
 * OAuth2SsoDefaultConfiguration for OAuth2 Single Sign On (SSO):
 * If the user only has {@code @EnableOAuth2Sso} but not on a WebSecurityConfigurerAdapter then one is
 * added with all paths secured and with an order that puts it ahead of the default HTTP Basic security chain in Spring Boot.
 *
 * curl -X GET http://localhost:9999/tclouds/list -v -L -u franck:spring -c cookies.txt
 *
 * @author Franck Andriano 2016
 */

/*@EnableBinding(TcloudChannels.class)
@IntegrationComponentScan */
@EnableOAuth2Sso        // @EnableOAuth2Client
//@EnableResourceServer   // Spring Boot 1.3, security.oauth2 in config!
@EnableFeignClients
@EnableZuulProxy        // @EnableDiscoveryClient @EnableCircuitBreaker
@SpringBootApplication  // @SpringBootConfiguration @EnableAutoConfiguration
public class TcloudClientApplication {

    public static void main(String[] args) {
		SpringApplication.run(TcloudClientApplication.class, args);
	}

}

@Component
class DiscoveryClientConsole implements CommandLineRunner {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(DiscoveryClientConsole.class);

    @Autowired
    private DiscoveryClient discoveryClient;

    @Autowired
    private LoadBalancerClient loadBalancerClient;

    @Override
    public void run(String... strings) throws Exception {

        // Spring Cloud Commons DiscoveryClient abstraction
        discoveryClient.getInstances("edge-service").forEach((ServiceInstance si) -> {
            logger.warn("["+si.getServiceId()+"] "+ ToStringBuilder.reflectionToString(si));
            logger.warn("["+si.getServiceId()+"] "+ si.getHost()+":"+si.getPort()+" secure: "+si.isSecure());
        });

        // Spring Cloud Commons LoadBalancerClient
        ServiceInstance edgechoose = loadBalancerClient.choose("edge-service");
        if (edgechoose != null)
            logger.warn("["+edgechoose.getServiceId()+"] "+"choose: "+edgechoose.getHost()+":"+edgechoose.getPort()+" secure: "+edgechoose.isSecure());

        // Spring Cloud Commons DiscoveryClient abstraction
        discoveryClient.getInstances("auth-service").forEach((ServiceInstance si) -> {
            logger.warn("["+si.getServiceId()+"] "+ ToStringBuilder.reflectionToString(si));
            logger.warn("["+si.getServiceId()+"] "+ si.getHost()+":"+si.getPort()+" secure: "+si.isSecure());
        });

        // Spring Cloud Commons LoadBalancerClient
        ServiceInstance authchoose = loadBalancerClient.choose("auth-service");
        if (authchoose != null)
            logger.warn("["+authchoose.getServiceId()+"] "+"choose: "+authchoose.getHost()+":"+authchoose.getPort()+" secure: "+authchoose.isSecure());


    }
}

/*
@MessagingGateway
interface TcloudWriter {
  @Gateway(requestChannel = "output")
  void write(String rn);
}

interface TcloudChannels {
@Output
MessageChannel output();
}
*/

@FeignClient("edge-service") // or tcloud-service
interface TcloudReader {                                // or tclouds
    @RequestMapping(method = RequestMethod.GET, value = "/tcloud-service/tclouds")  // GetMapping signature doesn't work with Feign!?
    Resources<Tcloud> read();
}

@FeignClient("edge-service") // or tcloud-service
interface TcloudMessageReader {                         // message
    @RequestMapping(method = RequestMethod.GET, value = "/tcloud-service/message")  // GetMapping signature doesn't work with Feign!?
    String read();
}

/**
 * Pre-defined custom RequestInterceptor for Feign Requests, uses the provided OAuth2ClientContext and Bearer tokens
 * within Authorization for header injection with current OAuth2ProtectedResourceDetails!
 *
 * See https://github.com/spring-cloud/spring-cloud-netflix/issues/675
 *
 * {@link OAuth2ClientContext oauth2ClientContext} see {@link DefaultOAuth2ClientContext }
 * {@link BaseOAuth2ProtectedResourceDetails resource} see config Oauth2 Resource!
 */
@Configuration
class OAuth2FeignConfig {

    @Bean
    @Autowired
    public RequestInterceptor oauth2FeignRequestInterceptor(
            OAuth2ClientContext oauth2ClientContext, BaseOAuth2ProtectedResourceDetails resource) {
        return new OAuth2FeignRequestInterceptor(oauth2ClientContext, resource);
    }
}


class Tcloud {

    private Long id;

    private String tcloudName;

    Tcloud() {  // JPA why !?
    }

    public Tcloud(String tcloudName) {
        this.tcloudName = tcloudName;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTcloudName() {
        return tcloudName;
    }

    public void setTcloudName(String tcloudName) {
        this.tcloudName = tcloudName;
    }

    @Override
    public String toString() {
        return "Tcloud { id: " + id + ", tcloudName: " + tcloudName + " }";
    }

}

@RestController
@RequestMapping("/tclouds")
class TcloudApiGateway {

    private final TcloudReader tcloudReader;

  /*  private final TcloudWriter tcloudWriter;*/

    @Autowired
    public TcloudApiGateway(TcloudReader tcloudReader/*, TcloudWriter tcloudWriter*/) {
        this.tcloudReader = tcloudReader;
        /*this.tcloudWriter = tcloudWriter;*/
    }

    /**
     * Get Rest Principal user through the OAuth2Sso!
     * */
    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }


    public Collection<String> fallback() {
        return new ArrayList<>();
    }

    @HystrixCommand(fallbackMethod = "fallback", commandProperties = {
            @HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "3000")
    })
    @GetMapping("/names")
    public Collection<String> names() {
        return this.tcloudReader
                .read()
                .getContent()
                .stream()
                .map(Tcloud::getTcloudName)
                .collect(Collectors.toList());
    }

    public Collection<Tcloud> listback() {
        return new ArrayList<Tcloud>();
    }

    @HystrixCommand(fallbackMethod = "listback")
    @GetMapping("/list")
    public Collection<Tcloud> list() {  // Return a list with ids!
        return this.tcloudReader
                .read()
                .getContent()
                .stream()
                .collect(Collectors.toList());
    }

    @GetMapping("/raw")
    public Object[] raw() {    // Return a raw list!
        return this.tcloudReader
                .read()
                .getContent()
                .stream()
                .sequential()
                .toArray();
    }

   /* @PostMapping()
    public void write(@RequestBody Tcloud tcloud) {
        this.tcloudWriter.write(tcloud.getTcloudName());
    }*/
}

@Controller
@RequestMapping("/tclouds-service")
class TcloudApiGatewayMvc {

    private final TcloudReader tcloudReader;
    private final TcloudMessageReader tcloudMessageReader;

    @Autowired
    public TcloudApiGatewayMvc(TcloudReader tcloudReader, TcloudMessageReader tcloudMessageReader) {
        this.tcloudReader = tcloudReader;
        this.tcloudMessageReader = tcloudMessageReader;
    }

    @GetMapping("/names")
    ModelAndView page() {
        ModelAndView modelAndView = new ModelAndView("tcloud");

        Resources<Tcloud> tclouds = this.tcloudReader.read();
        List<Object> data = new LinkedList<>();

        for (Tcloud tcloud : tclouds) {
            data.add(ImmutableMap.<String, Object>builder()
                    .put("id", tcloud.getId())
                    .put("tcloudName", tcloud.getTcloudName())
                    .build());
        }
        modelAndView.addObject("tclouds", data);
        modelAndView.addObject("message", this.tcloudMessageReader.read());

        return modelAndView;
    }

}

