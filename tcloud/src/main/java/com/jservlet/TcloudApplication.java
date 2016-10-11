package com.jservlet;

import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;

import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurerAdapter;
import org.springframework.hateoas.MediaTypes;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.integration.annotation.MessageEndpoint;
import org.springframework.integration.annotation.ServiceActivator;
import org.springframework.cloud.stream.annotation.Input;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.util.*;
import java.util.stream.Stream;

/**
 *  Tcould Service
 *
 *  @Author: Franck Andriano
 */

@EnableZuulProxy
@EnableDiscoveryClient
@SpringBootApplication
public class TcloudApplication {

    /**
     * Force to expose Tcloud.Long.id, with config defaultMediaType = MediaTypes.HAL_JSON!
     */
    @Configuration
    public class MyRepoRestAdapter extends RepositoryRestConfigurerAdapter {
        @Override
        public void configureRepositoryRestConfiguration(RepositoryRestConfiguration config) {
            config.exposeIdsFor(Tcloud.class);
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(TcloudApplication.class, args);
    }

}

interface TcloudChannels {
    @Input
    MessageChannel input();
}

@MessageEndpoint
class TcloudProcessor {

    private final TcloudRepository tcloudRepository;

    @ServiceActivator(inputChannel = "input")
    public void onMessage(Message<String> msg) {
        this.tcloudRepository.save(new Tcloud(msg.getPayload()));
    }

    @Autowired
    public TcloudProcessor(TcloudRepository tcloudRepository) {
        this.tcloudRepository = tcloudRepository;
    }
}

@Component
class SampleDataCLR implements CommandLineRunner {

    public final TcloudRepository tcloudRepository;

    @Autowired
    public SampleDataCLR(TcloudRepository tcloudRepository) {
        this.tcloudRepository = tcloudRepository;
    }

    @Override
    public void run(String... strings) throws Exception {
        Stream.of("Test1", "test2", "test3", "test4", "test5", "test6", "test7")
                .forEach(name -> tcloudRepository.save(new Tcloud(name)));
        tcloudRepository.findAll().forEach(System.out::println);
    }
}

// Supports dynamic re-configuration!
// curl -d{} http://localhost:8010/refresh
// ["message"]
@RefreshScope
@RestController
class MessageRestController {

    private final String value;

    @Autowired
    public MessageRestController(@Value("${message}") String value) {
        this.value = value;
    }

    @GetMapping("/message")
    String read() {
        return this.value;
    }

}

/**
 * Handles Rest responses.
 */
@RestController
class TcloudRestController {

    private final TcloudRepository tcloudRepository;

    @Autowired
    public TcloudRestController(TcloudRepository tcloudRepository) {
        this.tcloudRepository = tcloudRepository;
    }

    @GetMapping("/tclouds-service")
    Collection<Tcloud> tcloud(@RequestParam(value = "q", required = false) String q/*, final HttpRequest request*/) {
        if (StringUtils.isEmpty(q)) return this.tcloudRepository.findAll();
        else return this.tcloudRepository.findByTcloudName(q);
    }
}

/**
 * Handles the FreeMarker-powered view responses.
 */
@Controller
@RequestMapping("/tclouds")
class TcloudMvcController {

    private final TcloudRepository tcloudRepository;

    @Autowired
    public TcloudMvcController(TcloudRepository tcloudRepository) {
        this.tcloudRepository = tcloudRepository;
    }

    @GetMapping("/names")
    ModelAndView page() {
        ModelAndView modelAndView = new ModelAndView("tcloud");
        List<Tcloud> tclouds = this.tcloudRepository.findAll();
        List<Object> data = new LinkedList<>();
        for (Tcloud tcloud : tclouds) {
            data.add(ImmutableMap.<String, Object>builder()
                    .put("id", tcloud.getId())
                    .put("tcloudName", tcloud.getTcloudName())
                    .build());
        }
        modelAndView.addObject("tclouds", data);
        return modelAndView;
    }

}


/**
 * Spring Data JPA-powered <em>repository</em> interface.
 * Supports common operations like {@link #findAll()} and {@link #save(Object)} against JPA entities.
 * This particular repository deals in {@link com.jservlet.Tcloud tcloud} objects.
 *
 * curl -X GET -H "Content-Type: application/json" --url "http://localhost:8010/tclouds/search/by-name?rn=Test1"
 * curl -X GET -H "Content-Type: application/json" --url "http://localhost:8010/tclouds/search/by-id?rn=1"
 */
@RepositoryRestResource
interface TcloudRepository extends JpaRepository<Tcloud, Long> {

    @RestResource(path = "by-name")
    Collection<Tcloud> findByTcloudName(@Param("rn") String rn);

    @RestResource(path = "by-id")
    Collection<Tcloud> findById(@Param("rn") Long rn);

}

@Entity
class Tcloud {

    @Id
    @GeneratedValue
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

