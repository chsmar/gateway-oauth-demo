/*
 * Copyright 2012-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mcs.demo.cloud1;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import mcs.demo.cloud1.service.HelloWorldService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Configuration
@SpringBootApplication
@RestController
@EnableFeignClients
public class Resource1Application implements CommandLineRunner {
    private static final Logger log = LoggerFactory.getLogger(Resource1Application.class);
    public static final String X_AUTH_USER = "X-Auth-User";
    public static final String X_AUTH_TOKEN = "X-Auth-Token";
    @Autowired
    private HelloWorldService helloWorldService;

    @Override
    public void run(String... args) {
        System.out.println(this.helloWorldService.getHelloMessage());
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(Resource1Application.class, args);
    }

    @GetMapping("/api/auth")
    public ResponseEntity<Authentication> auth() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication);
    }

    @GetMapping("/api/principal")
    public ResponseEntity<Principal> principal(Principal principal) {
        return ResponseEntity.ok(principal);
    }

    @Autowired
    private Resource2 resource2;

    @GetMapping("/api/all/hello")
    public ResponseEntity<List<String>> allHello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String usr = authentication.getName();
        return ResponseEntity.ok(Arrays.asList("Authenticated: " + usr, this.helloWorldService.getHelloMessage(), resource2.hello().getBody(), resource2.publicHello().getBody()));
    }

    @GetMapping("/api/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok(this.helloWorldService.getHelloMessage());
    }

    @GetMapping("/public/hello")
    public ResponseEntity<String> publicHello() {
        return ResponseEntity.ok("Public: " + this.helloWorldService.getHelloMessage());
    }

    @FeignClient(name = "resource2", url = "http://localhost:8072")
    public interface Resource2 {
        @GetMapping("/api/hello")
        ResponseEntity<String> hello();

        @GetMapping("/public/hello")
        ResponseEntity<String> publicHello();
    }

    @Configuration
    @EnableResourceServer
    public static class ResourceServerConfig extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    //.addFilterAt(new CustomAuthFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                    .authorizeRequests()
                    .antMatchers("/api/**").authenticated()
                    .anyRequest().permitAll()
            ;
        }

        @Autowired
        private ResourceServerTokenServices defaultTokenServices;

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            TokenServicesDecorator decoratedTokenServices = new TokenServicesDecorator(defaultTokenServices);
            resources.tokenServices(decoratedTokenServices);
        }
    }

    public static class TokenServicesDecorator implements ResourceServerTokenServices {

        private final ResourceServerTokenServices delegate;

        public TokenServicesDecorator(ResourceServerTokenServices delegate) {
            this.delegate = delegate;
        }

        @Override
        public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
            String username = findHeader(X_AUTH_USER);
            if (username == null) {
                return delegate.loadAuthentication(accessToken);
            }
            String token = findHeader(X_AUTH_TOKEN);
            List<GrantedAuthority> authorities = new ArrayList<>();
            // add roles or authorities
            Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
            OAuth2Request oAuth2Request = new OAuth2Request(null, "client", null, true, null, null, null, null, null);
            OAuth2Authentication oauth = new OAuth2Authentication(oAuth2Request, auth);
            log.info("custom loadAuth: {} {}", username, oauth);
            return oauth;
        }

        @Override
        public OAuth2AccessToken readAccessToken(String accessToken) {
            return delegate.readAccessToken(accessToken);
        }

        private String findHeader(String headerKey) {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes == null) {
                return null;
            }
            HttpServletRequest request = attributes.getRequest();
            if (request == null) {
                return null;
            }
            return request.getHeader(headerKey);
        }
    }

    public static class CustomAuthFilter extends OncePerRequestFilter {
        private static final Logger log = LoggerFactory.getLogger(CustomAuthFilter.class);
        public static final String X_AUTH_USER = "X-Auth-User";
        public static final String X_AUTH_TOKEN = "X-Auth-Token";

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            log.info("Headers: {}", Collections.list(request.getHeaderNames()).stream().map(h -> new AbstractMap.SimpleEntry<>(h, request.getHeader(h))).collect(Collectors.toList()));
            String username = request.getHeader(X_AUTH_USER);
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
            if (currentAuth != null || username == null || request.getServletPath().startsWith("/public/")) {
                filterChain.doFilter(request, response);
                return;
            }
            String token = request.getHeader(X_AUTH_TOKEN);
            List<GrantedAuthority> authorities = new ArrayList<>();
            // add roles or authorities
            Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
            OAuth2Request oAuth2Request = new OAuth2Request(null, "client", null, true, null, null, null, null, null);
            OAuth2Authentication oauth = new OAuth2Authentication(oAuth2Request, auth);
            SecurityContextHolder.getContext().setAuthentication(oauth);
            filterChain.doFilter(request, response);
        }
    }

    @Configuration
    public static class FeignClientConfig {
        @Bean
        public RequestInterceptor customHeadersInterceptor() {
            return new RequestInterceptor() {
                @Override
                public void apply(RequestTemplate template) {
                    ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
                    if (attributes == null || template.url().startsWith("/public/")) {
                        return;
                    }
                    HttpServletRequest request = attributes.getRequest();
                    Enumeration<String> headerNames = request.getHeaderNames();
                    if (headerNames == null) {
                        return;
                    }
                    while (headerNames.hasMoreElements()) {
                        String headerName = headerNames.nextElement();
                        String headerValue = request.getHeader(headerName);
                        template.header(headerName, headerValue);
                    }
                }
            };
        }
    }
}
