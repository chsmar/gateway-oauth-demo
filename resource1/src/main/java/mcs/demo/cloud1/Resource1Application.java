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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Configuration
@EnableAutoConfiguration
@SpringBootApplication
@RestController
@EnableFeignClients
public class Resource1Application implements CommandLineRunner {

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

    @Autowired
    private Resource2 resource2;

    @GetMapping("/api/all/hello")
    public ResponseEntity<List<String>> allHello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String usr = authentication.getName();
        return ResponseEntity.ok(Arrays.asList("Authenticated: " + usr, this.helloWorldService.getHelloMessage(), resource2.hello().getBody()));
    }

    @GetMapping("/public/hello")
    public ResponseEntity<String> publicHello() {
        return ResponseEntity.ok("Public: " + this.helloWorldService.getHelloMessage());
    }

    @FeignClient(name = "resource2", url = "http://localhost:8072")
    public interface Resource2 {
        @GetMapping("/api/hello")
        ResponseEntity<String> hello();
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
                    .addFilterBefore(new CustomAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            ;
        }

        public static class CustomAuthenticationFilter extends OncePerRequestFilter {
            private static final Pattern API_PATTERN = Pattern.compile("^/api/.*");

            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                if (!API_PATTERN.matcher(request.getServletPath()).matches()) {
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
    }

    @Configuration
    public static class FeignClientConfig {
        private static final Pattern API_PATTERN = Pattern.compile("^/api/.*");

        @Bean
        public RequestInterceptor customHeadersInterceptor() {
            return new RequestInterceptor() {
                @Override
                public void apply(RequestTemplate template) {
                    if (!API_PATTERN.matcher(template.url()).matches()) {
                        return;
                    }
                    ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
                    if (attributes != null) {
                        HttpServletRequest request = attributes.getRequest();
                        String username = request.getHeader(X_AUTH_USER);
                        String token = request.getHeader(X_AUTH_TOKEN);

                        if (username != null) {
                            template.header(X_AUTH_USER, username);
                        }
                        if (token != null) {
                            template.header(X_AUTH_TOKEN, token);
                        }
                    }
                }
            };
        }
    }
}
