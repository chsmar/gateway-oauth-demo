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
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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
@EnableAutoConfiguration
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
    @EnableWebSecurity
    public static class ResourceServiceConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/api/**").authenticated()
                    .anyRequest().permitAll()
                    .and()
                    .addFilterBefore(new CustomAuthFilter(), UsernamePasswordAuthenticationFilter.class)
            ;
        }
    }

    public static class CustomAuthFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            log.info("Headers: {}", Collections.list(request.getHeaderNames()).stream().map(h -> new AbstractMap.SimpleEntry<>(h, request.getHeader(h))).collect(Collectors.toList()));
            if (request.getServletPath().startsWith("/public/")) {
                SecurityContextHolder.clearContext();
                filterChain.doFilter(request, response);
                return;
            }
            String username = request.getHeader(X_AUTH_USER);
            String token = request.getHeader(X_AUTH_TOKEN);
            if (username != null && token != null) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                // add roles or authorities
                Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            } else {
                SecurityContextHolder.clearContext();
            }
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
