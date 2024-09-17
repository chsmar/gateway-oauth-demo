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

import mcs.demo.cloud1.service.HelloWorldService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableAutoConfiguration
@SpringBootApplication
@RestController
@EnableFeignClients
public class Resource1Application implements CommandLineRunner {

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
        return ResponseEntity.ok(Arrays.asList(this.helloWorldService.getHelloMessage(), resource2.hello().getBody(), resource2.publicHello().getBody()));
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
}
