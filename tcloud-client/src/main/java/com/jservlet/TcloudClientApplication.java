package com.jservlet;

import com.google.common.collect.ImmutableMap;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixProperty;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;

import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
/*import org.springframework.cloud.stream.annotation.EnableBinding;
import org.springframework.cloud.stream.annotation.Output;*/

import org.springframework.hateoas.Resources;
/*import org.springframework.integration.annotation.Gateway;
import org.springframework.integration.annotation.IntegrationComponentScan;
import org.springframework.integration.annotation.MessagingGateway;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client; */
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.util.*;

import java.util.stream.Collectors;

/**
 *  Tcould Client
 *
 *  @Autor: Franck Andriano
 */

/*@EnableBinding(TcloudChannels.class)
@IntegrationComponentScan
@EnableOAuth2Client
@EnableResourceServer*/
@EnableCircuitBreaker
@EnableFeignClients
@EnableZuulProxy
@EnableResourceServer
@EnableDiscoveryClient
@SpringBootApplication
public class TcloudClientApplication {

    /**
     * http://localhost:9999/tclouds/list?access_token=443bd75c-60f5-40a5-856f-47f346683d87
     *
     * curl -d'{"tcloudName", "Nexus"}{"access_token", "b5e46da9-7ca7-47ef-93ac-3cd31fb93c7f"}' -H{"content type: application/hal+json"} localhost:9999/tclouds/names
     *
     */
	public static void main(String[] args) {
		SpringApplication.run(TcloudClientApplication.class, args);
	}

}

@Component
class DiscoveryClientConsole implements CommandLineRunner {

    private Logger logger = Logger.getLogger(getClass());

    @Autowired
    private DiscoveryClient discoveryClient;

    @Autowired
    private LoadBalancerClient loadBalancerClient;

    @Override
    public void run(String... strings) throws Exception {

        // Spring Cloud Commons DiscoveryClient abstraction
        discoveryClient.getInstances("tcloud-service").forEach((ServiceInstance si) -> {
            logger.warn("["+si.getServiceId()+"] "+ ToStringBuilder.reflectionToString(si));
            logger.warn("["+si.getServiceId()+"] "+ si.getHost()+":"+si.getPort()+" secure: "+si.isSecure());
        });

        // Spring Cloud Commons LoadBalancerClient
        ServiceInstance tchoose = loadBalancerClient.choose("tcloud-service");
        if (tchoose != null)
            logger.warn("["+tchoose.getServiceId()+"] "+"choose: "+tchoose.getHost()+":"+tchoose.getPort()+" secure: "+tchoose.isSecure());
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
@FeignClient("tcloud-service")
interface TcloudReader {
    @RequestMapping(method = RequestMethod.GET, value = "/tclouds")  // GetMapping signature doesn't work with Feign!?
    Resources<Tcloud> read();
}

@FeignClient("tcloud-service")
interface TcloudMessageReader {
    @RequestMapping(method = RequestMethod.GET, value = "/message")  // GetMapping signature doesn't work with Feign!?
    String read();
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
