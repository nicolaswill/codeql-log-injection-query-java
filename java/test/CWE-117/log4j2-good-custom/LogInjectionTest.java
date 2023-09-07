package com.example.restservice;

import java.net.URLEncoder;

import org.slf4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogInjectionTest {

    private final Logger log = null;

    @GetMapping("/bad")
    public String bad(@RequestParam(value = "username", defaultValue = "name") String username) {
        log.warn("User:'{}'", username);
        return username;
    }

    @GetMapping("/good")
    public String good(@RequestParam(value = "username", defaultValue = "name") String username)
            throws Exception {
        {
            // URL encoding
            String username_encoded = URLEncoder.encode(username, "UTF-8");
            log.warn("User:'{}'", username_encoded);
        }
        {
            // Base64 encoding
            String username_encoded = java.util.Base64.getEncoder().encodeToString(username.getBytes());
            log.warn("User:'{}'", username_encoded);
        }
        return username;
    }
}
