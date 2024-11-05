package ru.antonov.securitytest.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) throws IllegalArgumentException {
        try {
            return ResponseEntity.ok(authService.register(request));
        } catch (IllegalArgumentException e){
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    )  throws IllegalArgumentException  {
        try {
            return ResponseEntity.ok(authService.authenticate(request));
        }  catch (IllegalArgumentException e){
            return ResponseEntity.badRequest().build();
        }
    }
}
