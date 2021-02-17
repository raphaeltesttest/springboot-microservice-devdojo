package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.youtube.core.model.ApplicationUser;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.token.creator.TokenCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import static java.util.Collections.emptyList;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        log.info("Attempting authentication...");
        ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if(applicationUser == null)
            throw new UsernameNotFoundException("Unable to retrieve the username or password");

        log.info("Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadUserByUsername", applicationUser.getUsername());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());

        usernamePasswordAuthenticationToken.setDetails(applicationUser);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) {
        log.info("Authentication was successful for the user'{}', generating JWE token", auth.getName());

        SignedJWT signedJWT = tokenCreator.createSignedJWT(auth);

        String encryptedToken = tokenCreator.encryptToken(signedJWT);

        log.info("Token generated successfully , adding it to the response header");

        response.addHeader("Access-Control-Expose_Headers", "XSRF-TOKEN, " +jwtConfiguration.getHeader().getName());

        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() +encryptedToken);
    }

//    @SneakyThrows
//    private SignedJWT createSignedJWT (Authentication auth){
//        log.info("Starting to create the signed JWT");
//
//        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
//
//        JWTClaimsSet jwtClaimsSet = createJWTClaimsSet(auth, applicationUser);
//
//        KeyPair rsaKeys = generateKeyPair();
//
//        log.info("Building JWK from the RSA Keys");
//
//        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();
//
//        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
//                .jwk(jwk)
//                .type(JOSEObjectType.JWT)
//                .build(), jwtClaimsSet);
//
//        log.info("Signing the token with the private RSA key");
//
//        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());
//
//        signedJWT.sign(signer);
//
//        log.info("Serialized token '{}'", signedJWT.serialize());
//
//        return signedJWT;
//
//    }
//
//    private JWTClaimsSet createJWTClaimsSet(Authentication auth, ApplicationUser applicationUser) {
//        log.info("Creating the JwtClaimSet Object for '{}'", applicationUser);
//        return new JWTClaimsSet.Builder()
//                .subject(applicationUser.getUsername())
//                .claim("authorities", auth.getAuthorities()
//                        .stream()
//                        .map(GrantedAuthority::getAuthority)
//                        .collect(toList()))
//                .issuer("Http://academy.devdojo")
//                .issueTime(new Date())
//                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
//                .build();
//    }
//
//    @SneakyThrows
//    private KeyPair generateKeyPair(){
//        log.info("Generating RSA 2048 bits Keys");
//
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
//
//        generator.initialize(2048);
//
//        return generator.genKeyPair();
//    }
//
//    private String encryptToken (SignedJWT signedJWT) throws JOSEException {
//        log.info("Starting the encryptToken method");
//
//        DirectEncrypter directEncrypter = new DirectEncrypter((jwtConfiguration.getPrivateKey().getBytes()));
//
//        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
//                .contentType("JWT")
//                .build(), new Payload(signedJWT));
//
//        log.info("Encrypting token with system's private key");
//
//        jweObject.encrypt(directEncrypter);
//
//        log.info("Token encrypted");
//
//        return jweObject.serialize();
//    }

}
