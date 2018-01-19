package com.parkerneff.snoopapi;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.Key;
import java.security.KeyPair;




@RestController
public class TokenController {
    // https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-signature
// https://github.com/jwtk/jjwt
    @Autowired
    private KeyPair keyPair;

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public String generateToken(@RequestBody JwtRequest jwtRequest) {
        // Create RSA-signer with the private key
        Key key = MacProvider.generateKey();


       return Jwts.builder()
                .setSubject(jwtRequest.getSubject()).setClaims(jwtRequest.getAdditonalClaims())
                .signWith(SignatureAlgorithm.HS512, key)
                .compact();



    }

    @RequestMapping("/key")
    public byte[] greeting() {
        return keyPair.getPublic().getEncoded();

    }

}
