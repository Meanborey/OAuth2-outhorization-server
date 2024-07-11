package com.example.oauth2authorizationserver.controller;

import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@RestController
public class DemoController {
    @GetMapping("/public")
    Map<String,String> getPublic() {
        return Map.of("message", "Public API") ;
    }
    @GetMapping("/private")
    Map<String,String> getPrivate() {
        return Map.of("message", "Private API");
    }
}
