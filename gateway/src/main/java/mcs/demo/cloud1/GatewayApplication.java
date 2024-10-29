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

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import mcs.demo.cloud1.service.HelloWorldService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.AbstractMap;
import java.util.Collections;
import java.util.stream.Collectors;

@Configuration
@EnableZuulProxy
@SpringBootApplication
public class GatewayApplication implements CommandLineRunner {
    private static final Logger log = LoggerFactory.getLogger(GatewayApplication.class);
    public static final String X_AUTH_CFG = "X-Auth-Cfg";
    public static final String X_AUTH_USER = "X-Auth-User";
    public static final String X_AUTH_TOKEN = "X-Auth-Token";
    @Autowired
    private HelloWorldService helloWorldService;

    @Override
    public void run(String... args) {
        System.out.println(this.helloWorldService.getHelloMessage());
    }

    public static void main(String[] args) throws Exception {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Configuration
    @EnableResourceServer
    public static class ResourceServerConfig extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    .authorizeRequests()
                    .antMatchers(HttpMethod.OPTIONS).permitAll()
                    .antMatchers("/*/api/**").authenticated()
                    .anyRequest().permitAll();
        }
    }

    @Configuration
    public static class ZuulConfig {
        @Bean
        public ZuulFilter tokenRelayFilter() {
            return new ZuulFilter() {
                @Override
                public String filterType() {
                    return "route";
                }

                @Override
                public int filterOrder() {
                    return 10;
                }

                @Override
                public boolean shouldFilter() {
                    return true;
                }

                @Override
                public Object run() {
                    RequestContext ctx = RequestContext.getCurrentContext();
                    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                    System.out.println(auth);
                    HttpServletRequest request = ctx.getRequest();
                    log.info("Coming Headers: " + Collections.list(request.getHeaderNames()).stream().map(h -> new AbstractMap.SimpleEntry<>(h, request.getHeader(h))).collect(Collectors.toList()));
                    log.info("Init Zuul Headers: " +ctx.getZuulRequestHeaders());
                    String authHeader = HttpHeaders.AUTHORIZATION.toLowerCase();
                    ctx.getZuulRequestHeaders().put(authHeader, request.getHeader(HttpHeaders.AUTHORIZATION));
                    boolean customAuth = Boolean.TRUE.toString().equals(ctx.getRequest().getHeader(X_AUTH_CFG));
                    if (customAuth && auth != null && auth.getDetails() instanceof OAuth2AuthenticationDetails) {
                        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
                        ctx.addZuulRequestHeader(X_AUTH_USER, auth.getName());
                        ctx.addZuulRequestHeader(X_AUTH_TOKEN, details.getTokenValue());
                        //ctx.getZuulRequestHeaders().remove(authHeader);
                    }
                    log.info("Final Zuul Headers: " +ctx.getZuulRequestHeaders());
                    return null;
                }
            };
        }
    }
}
