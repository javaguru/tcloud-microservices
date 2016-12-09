package com.jservlet;

import com.google.common.collect.ImmutableMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;

import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
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
 *  Tcloud Service
 *
 *  @author Franck Andriano 2016
 */

@EnableResourceServer   // Spring Boot 1.3, security.oauth2 in config!
@EnableZuulProxy        // @EnableDiscoveryClient @EnableCircuitBreaker
@SpringBootApplication  // @SpringBootConfiguration @EnableAutoConfiguration
public class TcloudApplication {

    /**
     * Force to expose Tcloud.Long.id, with config defaultMediaType = MediaTypes.HAL_JSON!
     * (Consumers do not need to know your db ids, just for a demo...)
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


/**
 * Spring Data JPA-powered <em>repository</em> interface.
 * Supports common operations like {@link #findAll()} and {@link #save(Object)} against JPA entities.
 * This particular repository deals in {@link com.jservlet.Tcloud tcloud} objects.
 *
 * curl -X GET -H "Content-Type: application/json" --url "http://localhost:8010/tclouds/search/by-name?rn=Test1"
 * curl -X GET -H "Content-Type: application/json" --url "http://localhost:8010/tclouds/search/by-id?rn=1"
 */
@RepositoryRestResource
interface TcloudRepository extends JpaRepository<Tcloud, Long>{

    @RestResource(path = "by-name")
    Optional<Tcloud> findByTcloudName(@Param("rn") String rn);

    @RestResource(path = "by-id")
    Optional<Tcloud> findById(@Param("rn") Long rn);

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
    public Collection<Tcloud> tclouds() {
        return this.tcloudRepository.findAll();
    }

    @GetMapping("/tclouds-service/")
    public Tcloud tcloud(@RequestParam(value = "q") String q) {
        return this.tcloudRepository.findByTcloudName(q).isPresent() ? this.tcloudRepository.findByTcloudName(q).get() : null;
    }

    @GetMapping("/tclouds-service/{id}")
    public Tcloud tcloudId(@PathVariable(value = "id") Long id) {
        return this.tcloudRepository.findById(id).isPresent() ? this.tcloudRepository.findById(id).get() : null;
    }

    @PostMapping("/tclouds-service")
    public void save(@RequestBody Tcloud tcloud) {
        tcloudRepository.saveAndFlush(tcloud);
    }

    @PutMapping("/tclouds-service/{id}")
    public void update(@PathVariable(value = "id") Long id, @RequestBody Tcloud tcloud) {     // or RequestParam!?
        if (tcloudRepository.findById(id).isPresent()) {
            tcloud.setId(id);
            tcloudRepository.saveAndFlush(tcloud);
        }
    }

    @DeleteMapping("/tclouds-service/{id}")
    public void delete(@PathVariable(value = "id") Long id) {  // idem!
        if (tcloudRepository.findById(id).isPresent()) {
            tcloudRepository.delete(id);
        }
    }
}

/**
 * Handles the FreeMarker-powered view responses (Simple page service).
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
        ModelAndView model = new ModelAndView("tcloud");

        List<Tcloud> tclouds = this.tcloudRepository.findAll();
        List<Object> data = new LinkedList<>();
        tclouds.forEach(tcloud -> data.add(ImmutableMap.<String, Object>builder()
                    .put("id", tcloud.getId())
                    .put("tcloudName", tcloud.getTcloudName())
                    .build()));

        model.addObject("tclouds", data);
        return model;
    }
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

