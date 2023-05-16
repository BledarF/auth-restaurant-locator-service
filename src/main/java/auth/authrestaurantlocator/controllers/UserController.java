package auth.authrestaurantlocator.controllers;

import auth.authrestaurantlocator.models.User;
import auth.authrestaurantlocator.payload.AuthenticationResponse;
import auth.authrestaurantlocator.payload.LoginRequest;
import auth.authrestaurantlocator.payload.RegisterRequest;
import auth.authrestaurantlocator.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Objects;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            AuthenticationResponse response = userService.authenticate(loginRequest);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Set-Cookie", "accessToken=" + response.getAccessToken() + "; Path=/; HttpOnly");
            headers.add("Set-Cookie", "refreshToken=" + response.getRefreshToken() + "; Path=/; HttpOnly");
            return ResponseEntity.ok().headers(headers).body(response);
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid email or password");
        }
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest registerRequest){
        if (!registerRequest.getPassword().equals(registerRequest.getConfirmPassword())) {
            return ResponseEntity.badRequest().body("Passwords don't match");
        }
        ResponseEntity<String>  registerOutput = userService.register(registerRequest);
        return registerOutput;
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        userService.refreshToken(request,response);
    }

}
