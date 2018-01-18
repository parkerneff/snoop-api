package com.parkerneff.snoopapi;

import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;


@RestController
public class TokenController {

    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public String generateToken(@RequestBody Map<String, String> claims) {

        if (claims != null) {
            StringBuilder sb = new StringBuilder();
            for (String key : claims.keySet()) {
                sb.append(key);
                sb.append("=");
                sb.append(claims.get(key));
                sb.append(",");
            }
            return sb.toString();
        } else {
            return "error";
        }

    }
}
