package com.parkerneff.snoopapi;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
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
        //HMAC
        String token = null;
        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
             token = JWT.create()
                    .withIssuer("parkers-idp")
                    .withSubject(jwtRequest.getSubject())
                    .withArrayClaim("roles", jwtRequest.getRoles())
                    .sign(algorithm);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


       return  token;



    }

    @RequestMapping("/key")
    public byte[] greeting() {
        return keyPair.getPublic().getEncoded();

    }

}
