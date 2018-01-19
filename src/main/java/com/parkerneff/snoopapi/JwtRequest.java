package com.parkerneff.snoopapi;


import lombok.Getter;
import lombok.Setter;

import java.util.Map;

public class JwtRequest {
    @Getter @Setter private String subject;
    @Getter @Setter private String[] roles;
    @Getter @Setter private Map<String, Object> additonalClaims;

}
