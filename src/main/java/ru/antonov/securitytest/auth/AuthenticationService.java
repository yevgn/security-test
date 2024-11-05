package ru.antonov.securitytest.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.antonov.securitytest.config.JwtService;
import ru.antonov.securitytest.token.Token;
import ru.antonov.securitytest.token.TokenRepository;
import ru.antonov.securitytest.token.TokenType;
import ru.antonov.securitytest.user.Role;
import ru.antonov.securitytest.user.User;
import ru.antonov.securitytest.user.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest request){
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        
        userRepository.findByEmail(request.getEmail()).ifPresent(
                u -> { throw new IllegalArgumentException("user with this email exists");}
        );

        userRepository.save(user);

        var jwtToken = jwtService.generateToken(user);
        saveUserToken(jwtToken, user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userRepository.findByEmail(request.getEmail()).
                orElseThrow(() -> new IllegalArgumentException("incorrect email"));

        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(jwtToken, user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if(validUserTokens.isEmpty()){
            return;
        }
        validUserTokens.forEach(t -> {
            t.setRevoked(true);
            t.setExpired(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

     private void saveUserToken(String jwtToken, User user){
        var token = Token.builder()
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .token(jwtToken)
                .user(user)
                .build();
        tokenRepository.save(token);
    }

}
