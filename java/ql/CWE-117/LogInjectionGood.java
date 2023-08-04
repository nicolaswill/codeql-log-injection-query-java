package com.example.restservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
public class LogInjection {

    private final Logger log = LoggerFactory.getLogger(LogInjection.class);

    // /good?username=Guest'%0AUser:'Admin
    @GetMapping("/good")
    public String good(@RequestParam(value = "username", defaultValue = "name") String username) {
        String sanitizedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8.toString());
        log.warn("User:'{}'", sanitizedUsername);
        // The logging call above would result in "Guest%27%0AUser%3A%27Admin"
        return sanitizedUsername;
    }
}
