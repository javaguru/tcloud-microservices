package com.jservlet;

import org.apache.log4j.Logger;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A Minimal Security OAuth2 Server
 *
 * *************
 * Code grant
 * *************
 * Browse http (Past ACL with login/password : franck,spring as simple USER of this service)
 * http://localhost:9191/uaa/oauth/authorize?response_type=code&client_id=acme&redirect_uri=http://example.com&scope=read&state=97536
 * <p>
 * Redirect http:
 * http://example.com/?code=0HCEpS&state=97536
 * <p>
 * CODE found: code=0HCEpS
 * <p>
 * Curl url:
 * curl acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=authorization_code -d client_id=acme -d redirect_uri=http://example.com -d code=0HCEpS
 * <p>
 * Response http:
 * {"access_token":"9bf70492-6dad-40f4-9d6a-0237e5c1dec4","token_type":"bearer","refresh_token":"f9da3625-74d2-4692-8baa-0258e2e68123","expires_in":43199,"scope":"read"}
 * <p>
 * *************
 * Implicit Grant
 * *************
 * Browse http:
 * http://localhost:9191/uaa/oauth/authorize?response_type=token&client_id=acme&redirect_uri=http://example.com&scope=read&state=48532
 * <p>
 * Redirect http:
 * http://example.com/#access_token=9bf70492-6dad-40f4-9d6a-0237e5c1dec4&token_type=bearer&state=48532&expires_in=42393
 * <p>
 * TOKEN=9bf70492-6dad-40f4-9d6a-0237e5c1dec4
 * <p>
 * *************
 * Resource Owner Password Credentials Grant
 * *************
 * curl -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=password -d client_id=acme -d scope=read -d username=franck -d password=spring
 * {"access_token":"9bf70492-6dad-40f4-9d6a-0237e5c1dec4","token_type":"bearer","refresh_token":"f9da3625-74d2-4692-8baa-0258e2e68123","expires_in":42190,"scope":"read"}
 * <p>
 * TOKEN=9bf70492-6dad-40f4-9d6a-0237e5c1dec4
 * <p>
 * *************
 * Client Credentials Grant
 * *************
 * curl -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=client_credentials -d scope=read
 * {"access_token":"d43d97dc-794c-4ed7-8fd3-e81c498d32f4","token_type":"bearer","expires_in":43199,"scope":"read"}
 * <p>
 * TOKEN=d43d97dc-794c-4ed7-8fd3-e81c498d32f4
 * <p>
 * Use this TOKEN as a parameter of http request... access_token=9bf70492-6dad-40f4-9d6a-0237e5c1dec4
 *
 * @author Franck Andriano 2016
 */
@EnableDiscoveryClient
@EnableResourceServer // Spring Boot 1.3 replace @EnableOAuth2Resource Spring Boot 1.2
@SpringBootApplication
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}

// Enabled JpaRepository, see bootstrap.properties h2 database server config!
interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByUsername(String username);
}

interface ClientRepository extends JpaRepository<Client, Long> {
    Optional<Client> findByClientId(String clientId);
}

@Component
class OAuth2InitConfig implements CommandLineRunner {

    private Logger logger = Logger.getLogger(getClass());

    private final AccountRepository accountRepository;
    private final ClientRepository clientRepository;

    @Autowired
    public OAuth2InitConfig(AccountRepository accountRepository, ClientRepository clientRepository) {
        this.accountRepository = accountRepository;
        this.clientRepository = clientRepository;
    }

    @Override
    public void run(String... strings) throws Exception {
        if (accountRepository.findAll().isEmpty()) {
            Stream.of("root,toor", "franck,spring", "admin,boot", "admin,cloud")
                    .map(x -> x.split(","))
                    .forEach(tpl -> accountRepository.save(new Account(tpl[0], tpl[1], true)));
            logger.warn("AccountRepository creation:");
        } else
            logger.warn("AccountRepository injection:");
        accountRepository.findAll().forEach(logger::warn);

        if (clientRepository.findAll().isEmpty()) {
            Stream.of("acme,acmesecret", "mobile,secret", "html5,secret")
                    .map(x -> x.split(","))
                    .forEach(tpl -> clientRepository.save(new Client(tpl[0], tpl[1])));
            logger.warn("ClientRepository creation:");
        } else
            logger.warn("ClientRepository injection:");
        clientRepository.findAll().forEach(logger::warn);
    }
}

@Configuration
class OAuth2ServerConfig {

    private final ClientRepository clientRepository;
    private final AccountRepository accountRepository;

    @Autowired
    public OAuth2ServerConfig(AccountRepository accountRepository, ClientRepository clientRepository) {
        this.accountRepository = accountRepository;
        this.clientRepository = clientRepository;
    }

    @Bean
    ClientDetailsService clientDetailsService() {
        return clientId -> clientRepository.findByClientId(clientId)
                .map(client -> {
                    BaseClientDetails details = new BaseClientDetails(
                            client.getClientId(),
                            null,
                            client.getScopes(),
                            client.getAuthorizedGrantTypes(),
                            client.getAuthorities(),
                            client.getRegisteredRedirectUri()
                    );
                    details.setClientSecret(client.getSecret());
                    details.setAutoApproveScopes(Arrays.asList(client.getAutoApproveScopes().split(",")));
                    details.setAccessTokenValiditySeconds(3600);
                    details.setRefreshTokenValiditySeconds(200);
                    return details;
                })
                .orElseThrow(() -> new ClientRegistrationException(String.format("no client %s registered", clientId)));
    }

    @Bean
    UserDetailsService userDetailsService() {
        return username -> accountRepository.findByUsername(username)
                .map(account -> {
                    boolean active = account.isActive();
                    return new User(
                            account.getUsername(),
                            account.getPassword(),
                            active, active, active, active,
                            ("root".equals(username)) ?
                                    AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN", "ROLE_SUPERVISOR") :
                                    AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")
                    );
                })
                .orElseThrow(() -> new UsernameNotFoundException(String.format("username %s not found!", username)));
    }
}

/**
 * Write user
 * curl -v -X PUT -d "username=Nexus" -d "password=Nexus6" localhost:9191/uaa/user?access_token=19474b0f-595b-42f8-867e-4bf234383b9e
 * <p>
 * Update user
 * curl -v -X POST -d "username=Nexus" -d "password=NexusX" localhost:9191/uaa/user?access_token=19474b0f-595b-42f8-867e-4bf234383b9e&username=Nexus
 * <p>
 * Delete user
 * curl -v -X DELETE localhost:9191/uaa/user?access_token=19474b0f-595b-42f8-867e-4bf234383b9e&username=Nexus
 * <p>
 * Raw users
 * curl -v localhost:9191/uaa/raw?access_token=19474b0f-595b-42f8-867e-4bf234383b9e
 * <p>
 * User Exceptions:
 * {"timestamp":1475961178416,"status":500,"error":"Internal Server Error","message":"User already exist!","path":"/uaa/user"}
 * {"timestamp":1475961178416,"status":500,"error":"Internal Server Error","message":"Unknown user: Fox","path":"/uaa/user"}
 * <p>
 * Grant user
 * curl -v -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=password -d client_id=acme -d scope=openid -d username=franck -d password=spring
 */
@RestController
class PrincipalRestController {

    private Logger logger = Logger.getLogger(getClass());

    private final AccountRepository accountRepository;

    @Autowired
    public PrincipalRestController(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @GetMapping("/user")
    public Principal principal(Principal principal) {
        return principal;
    }

    @PutMapping("/user")
    public void write(@RequestParam(value = "username") String username,
                      @RequestParam(value = "password") String password,
                      HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.isUserInRole("ROLE_SUPERVISOR")) {
            if (accountRepository.findByUsername(username).isPresent())
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "User already exist!");
            else {
                Account account = new Account(username, password, true);
                accountRepository.save(account);
                logger.warn("AccountRepository injection: " + account);
            }
        } else response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @PostMapping("/user")
    public void update(@RequestParam(value = "username") String username,
                       @RequestParam(value = "password") String password,
                       HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.isUserInRole("ROLE_SUPERVISOR") || (request.isUserInRole("ROLE_ADMIN") && request.getUserPrincipal().getName().equals(username))) {
            if (!accountRepository.findByUsername(username).isPresent())
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unknown user: " + username);
            else {
                Optional<Account> optional = accountRepository.findByUsername(username);
                Account account = optional.get();
                account.setPassword(password);
                accountRepository.saveAndFlush(account);
                logger.warn("AccountRepository update user: " + optional.get().getUsername());
            }
        } else response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @DeleteMapping("/user")
    public void delete(@RequestParam(value = "username") String username,
                       HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.isUserInRole("ROLE_SUPERVISOR") || (request.isUserInRole("ROLE_ADMIN") && request.getUserPrincipal().getName().equals(username))) {
            if (!accountRepository.findByUsername(username).isPresent())
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unknown user: " + username);
            else {
                Optional<Account> optional = accountRepository.findByUsername(username);
                accountRepository.delete(optional.get().getId());
                logger.warn("AccountRepository delete: " + optional.toString());
            }
        } else response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @GetMapping("/raw")
    public Object[] raw(HttpServletRequest request) { // Return a raw list!
        if (request.isUserInRole("ROLE_SUPERVISOR")) return accountRepository.findAll().toArray();
        else return null;
    }
}

@Configuration
@EnableAuthorizationServer
class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final ClientDetailsService clientDetailsService;

    @Autowired(required = false)
    public AuthorizationServerConfig(AuthenticationManager authenticationManager, ClientDetailsService clientDetailsService) {
        this.authenticationManager = authenticationManager;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager);
    }

}

// See bootstrap.properties h2 database server config!
// DROP TABLE IF EXISTS ACCOUNT;
// CREATE TABLE ACCOUNT(ID BIGINT auto_increment PRIMARY KEY,USERNAME VARCHAR(255),PASSWORD VARCHAR(255),ACTIVE BOOLEAN);
@Entity
class Account {

    @Id
    @GeneratedValue
    private Long id;

    @NotEmpty
    private String username, password;

    private boolean active;

    Account() { // JPA why !?
    }

    public Account(String username, String password, boolean active) {
        this.username = username;
        this.password = password;
        this.active = active;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isActive() {
        return active;
    }

    @Override
    public String toString() {
        return "Account { id: " + id + ", username:" + username + ", password: " + password + ", active: " + active + " }";
    }
}

// DROP TABLE IF EXISTS CLIENT;
// CREATE TABLE CLIENT(ID BIGINT auto_increment PRIMARY KEY,CLIENT_ID VARCHAR(255),SECRET VARCHAR(255),SCOPES VARCHAR(255),
// AUTHORIZED_GRANT_TYPES VARCHAR(255),AUTHORITIES VARCHAR(255),AUTO_APPROVE_SCOPES VARCHAR(255), REGISTERED_REDIRECT_URI VARCHAR(1020));
@Entity
class Client {

    @Id
    @GeneratedValue
    private Long id;

    @NotEmpty
    private String clientId, secret;
    private String scopes = from("read", "write");
    private String authorizedGrantTypes = from("client_credentials", "implicit", "authorization_code", "refresh_token", "password");
    private String authorities = from("ROLE_USER", "ROLE_ADMIN");
    private String autoApproveScopes = from("true");
    private String registeredRedirectUri = from();

    public String getScopes() {
        return scopes;
    }

    public String getAuthorizedGrantTypes() {
        return authorizedGrantTypes;
    }

    public String getAuthorities() {
        return authorities;
    }

    public String getAutoApproveScopes() {
        return autoApproveScopes;
    }

    public String getRegisteredRedirectUri() {
        return registeredRedirectUri;
    }

    private static String from(String... arr) {
        return Arrays.stream(arr).collect(Collectors.joining(","));
    }

    public Client(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.secret = clientSecret;
    }

    Client() { // JPA why !?
    }

    public Long getId() {
        return id;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSecret() {
        return secret;
    }

    @Override
    public String toString() {
        return "Client { clientId: " + clientId + ", secret: " + secret + ", scopes: [" + scopes +
                "], authorizedGrantTypes: [" + authorizedGrantTypes + "], authorities: [" + authorities +
                "] autoApproveScopes: [" + autoApproveScopes + "], registeredRedirectUri: [" + registeredRedirectUri + "] }";
    }
}