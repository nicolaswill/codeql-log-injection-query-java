package com.example.restservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogInjection {

    private final Logger log = LoggerFactory.getLogger(LogInjection.class);

    // /baddataloss?username=Guest'%0AUser:'Admin
    @GetMapping("/baddataloss")
    public String baddataloss(@RequestParam(value = "username", defaultValue = "name") String username) {
        // Sanitizing unwanted characters from the username before logging results in
        // irreversible data-loss. If special characters are also undesirable
        // (e.g. for JSON/HTML encodings), then the sanitization must discard
        // those characters as well, leading to further data-loss and silent exclusion
        // of common non-alphanumeric characters (e.g. punctuation).
        log.warn("User:'{}'", username.replaceAll("[^a-zA-Z]", ""));

        // Even if log injection was avoided, further processing of unsanitized input
        // could lead to other vulnerabilities downstream.
        return username;
    }
}
