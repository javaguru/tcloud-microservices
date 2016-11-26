package com.jservlet;

import org.apache.log4j.Logger;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import javax.persistence.Id;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A Minimal Security OAuth2 Server
 *
 * Active OAuth2 with Openid JWT (Jason Web Token) SHA256 with RSA private/public keys in config!
 *
 * curl http://localhost:9191/uaa/oauth/token_key
 * {"alg":"SHA256withRSA",
 *  "value":"-----BEGIN PUBLIC KEY-----
 *  MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNQZKqTlO/+2b4ZdhqGJzGBDltb5PZmBz1ALN2YLvt341pH6i5mO1V9cX5Ty1LM70fKfnIoYUP4KCE
 *  33dPnC7LkUwE/myh1zM6m8cbL5cYFPyP099thbVxzJkjHWqywvQih/qOOjliomKbM9pxG8Z1dB26hL9dSAZuA8xExjlPmQIDAQAB
 *  -----END PUBLIC KEY-----"}
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
interface UsersRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByUsername(String username);
}

interface AuthoritiesRepository extends JpaRepository<Authorities, Long> {
    List<Authorities> findByUsername(String username);
}

interface ClientRepository extends JpaRepository<Client, Long> {
    Optional<Client> findByClientId(String clientId);
}

@Component
class OAuth2InitConfig implements CommandLineRunner {

    private Logger logger = Logger.getLogger(getClass());

    private final UsersRepository usersRepository;
    private final AuthoritiesRepository authoritiesRepository;
    private final ClientRepository clientRepository;

    @Autowired
    public OAuth2InitConfig(UsersRepository usersRepository, AuthoritiesRepository authoritiesRepository,
                            ClientRepository clientRepository) {
        this.usersRepository = usersRepository;
        this.authoritiesRepository = authoritiesRepository;
        this.clientRepository = clientRepository;
    }

    @Override
    public void run(String... strings) throws Exception {

        // Users
        if (usersRepository.findAll().isEmpty()) {
            Stream.of("root,toor", "franck,spring", "admin,cloud").map(x -> x.split(","))
                    .forEach(tpl -> usersRepository.save(new Users(tpl[0], new BCryptPasswordEncoder(10).encode(tpl[1]), true)));
            logger.warn("UsersRepository creation:");
        }
        else logger.warn("UsersRepository injection:");
        usersRepository.findAll().forEach(logger::warn);

        // Authorities
        if (authoritiesRepository.findAll().isEmpty()) {
            Stream.of("root,ROLE_USER", "franck,ROLE_USER", "admin,ROLE_USER").map(x -> x.split(","))
                    .forEach(tpl -> authoritiesRepository.save(new Authorities(tpl[0], tpl[1])));
            Stream.of("root,ROLE_ADMIN", "franck,ROLE_ADMIN", "admin,ROLE_ADMIN").map(x -> x.split(","))
                    .forEach(tpl -> authoritiesRepository.save(new Authorities(tpl[0], tpl[1])));
            // root only
            authoritiesRepository.save(new Authorities("root", "ROLE_SUPERVISOR"));
            logger.warn("authoritiesRepository creation:");
        }
        else logger.warn("authoritiesRepository injection:");
        authoritiesRepository.findAll().forEach(logger::warn);

        // Clients
        if (clientRepository.findAll().isEmpty()) {
            Stream.of("acme,acmesecret", "mobile,secret", "html5,secret").map(x -> x.split(","))
                    .forEach(tpl -> clientRepository.save(new Client(tpl[0], new BCryptPasswordEncoder(10).encode(tpl[1]))));
            logger.warn("ClientRepository creation:");
        }
        else logger.warn("ClientRepository injection:");
        clientRepository.findAll().forEach(logger::warn);
    }
}

@Configuration
class OAuth2ServerConfig {

    private Logger logger = Logger.getLogger(getClass());

    private final ClientRepository clientRepository;
    private final AuthoritiesRepository authoritiesRepository;
    private final UsersRepository usersRepository;

    @Autowired
    public OAuth2ServerConfig(UsersRepository usersRepository, AuthoritiesRepository authoritiesRepository,
                              ClientRepository clientRepository) {
        this.usersRepository = usersRepository;
        this.authoritiesRepository = authoritiesRepository;
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
                details.setAccessTokenValiditySeconds(1800);  // 30mn Token < 1h RefreshToken!
                details.setRefreshTokenValiditySeconds(3600);
                return details;
            })
            .orElseThrow(() -> new ClientRegistrationException(String.format("no client %s registered", clientId)));
    }

    @Bean
    UserDetailsService userDetailsService() throws RuntimeException {
        return username -> usersRepository.findByUsername(username)
            .map(user -> {
                boolean active = user.isActive();
                List<Authorities> authorities = authoritiesRepository.findByUsername(username);
                List<GrantedAuthority> grantedAuthorities = new ArrayList<>(authorities.size());
                authorities.forEach(authority -> grantedAuthorities.add(new SimpleGrantedAuthority(authority.getAuthority())));
                return new User(
                        user.getUsername(),
                        user.getPassword(),
                        active, active, active, active,
                        grantedAuthorities
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

    private final UsersRepository usersRepository;

    @Autowired
    public PrincipalRestController(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
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
            if (usersRepository.findByUsername(username).isPresent())
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "User already exist!");
            else {
                Users user = new Users(username, new BCryptPasswordEncoder(10).encode(password), true);
                usersRepository.save(user);
                logger.warn("UsersRepository injection: " + user);
            }
        } else response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @PostMapping("/user")
    public void update(@RequestParam(value = "username") String username,
                       @RequestParam(value = "password") String password,
                       HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.isUserInRole("ROLE_SUPERVISOR") || (request.isUserInRole("ROLE_ADMIN") && request.getUserPrincipal().getName().equals(username))) {
            if (!usersRepository.findByUsername(username).isPresent())
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unknown user: " + username);
            else {
                Optional<Users> optional = usersRepository.findByUsername(username);
                Users user = optional.get();
                user.setPassword(new BCryptPasswordEncoder(10).encode(password));
                usersRepository.saveAndFlush(user);
                logger.warn("UsersRepository update user: " + optional.get().getUsername());
            }
        } else response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @DeleteMapping("/user")
    public void delete(@RequestParam(value = "username") String username,
                       HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.isUserInRole("ROLE_SUPERVISOR") || (request.isUserInRole("ROLE_ADMIN") && request.getUserPrincipal().getName().equals(username))) {
            if (!usersRepository.findByUsername(username).isPresent())
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unknown user: " + username);
            else {
                Optional<Users> optional = usersRepository.findByUsername(username);
                usersRepository.delete(optional.get());
                logger.warn("UsersRepository delete: " + optional.toString());
            }
        } else response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @GetMapping("/raw")
    public Object[] raw(HttpServletRequest request) { // Return a raw list!
        if (request.isUserInRole("ROLE_SUPERVISOR")) return usersRepository.findAll().toArray();
        else return null;
    }
}

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource;

    private final UserDetailsService userDetailsService;

    @Autowired
    public WebSecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests().antMatchers(HttpMethod.OPTIONS, "/oauth/token", "/oauth/token_key").permitAll()
            .and()
                .csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // @formatter:on
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(new BCryptPasswordEncoder(10));
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder(10));
    }
}

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class CorsFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse response = (HttpServletResponse) res;
        HttpServletRequest request = (HttpServletRequest) req;
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
        response.setHeader("Access-Control-Max-Age", "1800");
        response.setHeader("Access-Control-Allow-Headers", "origin,accept,x-requested-with,content-type,access-control-request-method,access-control-request-headers,authorization");
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            chain.doFilter(req, res);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {  }

    @Override
    public void destroy() { }
}

@Configuration
@EnableAuthorizationServer
class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private Logger logger = Logger.getLogger(getClass());

    @Value("${config.oauth2.private-key}")
    private String privateKey;

    @Value("${config.oauth2.public-key}")
    private String publicKey;

    private final AuthenticationManager authenticationManager;
    private final ClientDetailsService clientDetailsService;
    private final UserDetailsService userDetailsService;

    @Bean
    public JwtAccessTokenConverter tokenEnhancer() {
        logger.warn("Initializing JWT with public key:\n" + publicKey);
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(privateKey);
        converter.setVerifierKey(publicKey);
        return converter;
    }

    @Bean
    public JwtTokenStore tokenStore() {  // Handle OAuth2 refresh JwtToken!
        return new JwtTokenStore(tokenEnhancer());
    }

    @Autowired
    public AuthorizationServerConfig(AuthenticationManager authenticationManager,
                                     ClientDetailsService clientDetailsService, UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.clientDetailsService = clientDetailsService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(clientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // @formatter:off
        endpoints
                .tokenStore(tokenStore())
                .accessTokenConverter(tokenEnhancer())
                .authenticationManager(authenticationManager).userDetailsService(userDetailsService);
        // @formatter:on
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer server) throws Exception {
        server.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
                .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
    }
}

// See bootstrap.properties h2 database server config!
// DROP TABLE IF EXISTS USERS;
// create table users(ID BIGINT auto_increment PRIMARY KEY, username varchar_ignorecase(50) not null unique, password varchar_ignorecase(255) not null, enabled boolean not null);
@Entity
class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty
    private String username, password;

    private boolean enabled;

    Users() { // JPA why !?
    }

    public Users(String username, String password, boolean enabled) {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
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
        return enabled;
    }

    @Override
    public String toString() {
        return "User { id:" + id + ", username:" + username + ", password: " + password + ", enabled: " + enabled + " }";
    }
}

// DROP TABLE IF EXISTS authorities;
// create table authorities (ID BIGINT auto_increment PRIMARY KEY, username varchar_ignorecase(50) not null, authority varchar_ignorecase(50) not null, constraint fk_authorities_users foreign key(username) references users(username));
// create unique index ix_auth_username on authorities (username, authority);
@Entity
class Authorities {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty
    @JoinTable(name = "users", joinColumns = @JoinColumn(name = "username"))
    private String username;

    @NotEmpty
    private String authority;

    Authorities() { // JPA why !?
    }

    public Authorities(String username, String authority) {
        this.username = username;
        this.authority = authority;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String toString() {
        return "Authority { id:" + id + ", username:" + username + ", authority: " + authority + " }";
    }
}

// Customized oauth_client_details table
// DROP TABLE IF EXISTS CLIENT;
// CREATE TABLE CLIENT(ID BIGINT auto_increment PRIMARY KEY,CLIENT_ID VARCHAR(255),SECRET VARCHAR(255),SCOPES VARCHAR(255),
// AUTHORIZED_GRANT_TYPES VARCHAR(255),AUTHORITIES VARCHAR(255),AUTO_APPROVE_SCOPES VARCHAR(255), REGISTERED_REDIRECT_URI VARCHAR(1024));
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