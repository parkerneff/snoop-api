package com.parkerneff.snoopapi;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.BDDAssertions.then;
import static org.junit.Assert.*;

/**
 * Basic integration tests for service demo application.
 *
 * @author Dave Syer
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"management.port=0"})
public class RestEndpointTests {

    @LocalServerPort
    private int port;

    @Value("${local.management.port}")
    private int mgt;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Autowired
    private PublicKey publicKey;

    @Test
    public void shouldReturn200WhenSendingRequestToController() throws Exception {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> entity = this.testRestTemplate.getForEntity(
                "http://localhost:" + this.port + "/greeting", Map.class);

        then(entity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void shouldReturn200WhenSendingRequestToManagementEndpoint() throws Exception {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> entity = this.testRestTemplate.getForEntity(
                "http://localhost:" + this.mgt + "/info", Map.class);

        then(entity.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    public void getTokenValidPublicKey() throws Exception {
        @SuppressWarnings("rawtypes")
        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setSubject("parkerneff");


        jwtRequest.setRoles(new String[]{"admin", "user"});
        HttpEntity<JwtRequest> request = new HttpEntity<>(jwtRequest);
        String token = this.testRestTemplate.postForObject("http://localhost:" + this.port + "/token", request, String.class);
        System.out.println("TOKEN=" + token);
        assertNotNull(token);


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("parker-idp") // whom the JWT needs to have been issued by
                .setExpectedAudience("Audience") // to whom the JWT is intended for
                .setVerificationKey(publicKey) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                AlgorithmIdentifiers.RSA_USING_SHA256))
                .build(); // create the JwtConsumer instance

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        } catch (InvalidJwtException e) {
           fail(e.getMessage());
        }


    }
    @Test
    public void getTokenInvalidPublicKey() throws Exception {
        @SuppressWarnings("rawtypes")





        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setSubject("parkerneff");


        jwtRequest.setRoles(new String[]{"admin", "user"});





        HttpEntity<JwtRequest> request = new HttpEntity<>(jwtRequest);
        String token = this.testRestTemplate.postForObject("http://localhost:" + this.port + "/token", request, String.class);
        System.out.println("TOKEN=" + token);
        assertNotNull(token);

        // Generate an new RSA key pair, the public key should not match the private key used to sign the JWT
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("parker-idp") // whom the JWT needs to have been issued by
                .setExpectedAudience("Audience") // to whom the JWT is intended for
                .setVerificationKey(rsaJsonWebKey.getPublicKey()) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                AlgorithmIdentifiers.RSA_USING_SHA256))
                .build(); // create the JwtConsumer instance

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            fail("should have got a invalid key exception");
        } catch (InvalidJwtException e) {
            System.out.println("Cool I got=" + e.getMessage());

        }


    }

    @Test
    public void testValidJwk() throws Exception {
        @SuppressWarnings("rawtypes")



        HttpsJwks httpsJkws = new HttpsJwks("http://localhost:" + this.port + "/jwks");
        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setSubject("parkerneff");


        jwtRequest.setRoles(new String[]{"admin", "user"});
        HttpEntity<JwtRequest> request = new HttpEntity<>(jwtRequest);
        String token = this.testRestTemplate.postForObject("http://localhost:" + this.port + "/token", request, String.class);
        System.out.println("TOKEN=" + token);
        assertNotNull(token);


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("parker-idp") // whom the JWT needs to have been issued by
                .setExpectedAudience("Audience") // to whom the JWT is intended for
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .build(); // create the JwtConsumer instance

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        } catch (InvalidJwtException e) {
            fail(e.getMessage());
        }


    }
}
