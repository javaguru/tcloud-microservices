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
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;

import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.validation.constraints.Size;
import java.security.Principal;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * A Minimal Security OAuth2 Server
 *
 * @links http://docs.spring.io/spring-security/site/docs/current/reference/html/appendix-schema.html
 *
 * *************
 * Code grant
 * *************
 * Browse http (Past ACL with login/password : franck,spring as simple USER of this service)
 * http://localhost:9191/uaa/oauth/authorize?response_type=code&client_id=acme&redirect_uri=http://example.com&scope=webshop&state=97536
 *
 * Redirect http:
 * http://example.com/?code=0HCEpS&state=97536
 *
 * CODE found: code=0HCEpS
 *
 * Curl url:
 * curl acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=authorization_code -d client_id=acme -d redirect_uri=http://example.com -d code=0HCEpS
 *
 * Response http:
 * {"access_token":"9bf70492-6dad-40f4-9d6a-0237e5c1dec4","token_type":"bearer","refresh_token":"f9da3625-74d2-4692-8baa-0258e2e68123","expires_in":43199,"scope":"webshop"}
 *
 * *************
 * Implicit Grant
 * *************
 * Browse http:
 * http://localhost:9191/uaa/oauth/authorize?response_type=token&client_id=acme&redirect_uri=http://example.com&scope=webshop&state=48532
 *
 * Redirect http:
 * http://example.com/#access_token=9bf70492-6dad-40f4-9d6a-0237e5c1dec4&token_type=bearer&state=48532&expires_in=42393
 *
 * TOKEN=9bf70492-6dad-40f4-9d6a-0237e5c1dec4
 *
 * *************
 * Resource Owner Password Credentials Grant
 * *************
 * curl -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=password -d client_id=acme -d scope=webshop -d username=franck -d password=spring
 * {"access_token":"9bf70492-6dad-40f4-9d6a-0237e5c1dec4","token_type":"bearer","refresh_token":"f9da3625-74d2-4692-8baa-0258e2e68123","expires_in":42190,"scope":"webshop"}
 *
 * TOKEN=9bf70492-6dad-40f4-9d6a-0237e5c1dec4
 *
 * *************
 * Client Credentials Grant
 * *************
 * curl -s acme:acmesecret@localhost:9191/uaa/oauth/token -d grant_type=client_credentials -d scope=webshop
 * {"access_token":"d43d97dc-794c-4ed7-8fd3-e81c498d32f4","token_type":"bearer","expires_in":43199,"scope":"webshop"}
 *
 * TOKEN=d43d97dc-794c-4ed7-8fd3-e81c498d32f4
 *
 * Use this TOKEN as a parameter of http request... access_token=9bf70492-6dad-40f4-9d6a-0237e5c1dec4
 *
 * @Author: Franck Andriano
 */
@EnableDiscoveryClient
@EnableResourceServer
@SpringBootApplication
public class AuthServiceApplication  {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}

interface AccountRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByUsername(String username);
}

@Service
class AccountUserDetailsService implements UserDetailsService {

    private final AccountRepository accountRepository;

    public AccountRepository getAccountRepository() {
        return accountRepository;
    }

    @Autowired
    public AccountUserDetailsService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.accountRepository.findByUsername(username)
                .map(account -> new User(
                        account.getUsername(),
                        account.getPassword(),
                        account.isActive(), account.isActive(), account.isActive(), account.isActive(),
                        AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")
                ))
                .orElseThrow(() -> new UsernameNotFoundException("couldn't find it!"));
    }
}

@Component
class AccountCLR implements CommandLineRunner {

    private Logger logger = Logger.getLogger(getClass());

    private final AccountRepository accountRepository;

    @Autowired
    public AccountCLR(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public void run(String... strings) throws Exception {
        if (accountRepository.findAll().isEmpty()) {
            Stream.of("root,toor","franck,spring", "admin,boot", "admin,cloud")
                    .map(x -> x.split(","))
                    .forEach(tpl -> accountRepository.save(new Account(tpl[0], tpl[1], true)));

            logger.warn("AccountRepository creation:");
        } else
            logger.warn("AccountRepository injection:");

        accountRepository.findAll().forEach(logger::warn);
    }
}


@RestController
class PrincipalRestController {

   @GetMapping("/user")
    public Principal principal(Principal principal) {
        return principal;
    }

}



@Configuration
@EnableAuthorizationServer
class OAuth2ServerConfig extends AuthorizationServerConfigurerAdapter {

    private Logger logger = Logger.getLogger(getClass());

    private final AuthenticationManager authenticationManager;

    @Autowired(required = false)
    public OAuth2ServerConfig (AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
            .inMemory()
            .withClient("acme").secret("acmesecret")
            .authorizedGrantTypes("client_credentials", "implicit", "password", "authorization_code", "refresh_token")
            .scopes("webshop");
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(this.authenticationManager);
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
    @Size(min = 1,max = 255)
    private String username;



    @NotEmpty
    @Size(min = 1,max = 255)
    private String password;

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
        return "Account { id: " + id + ", username:" + username+ ", password: " + password + ", active: " + active + " }";
    }
}