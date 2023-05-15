package auth.authrestaurantlocator.services;

import auth.authrestaurantlocator.config.JwtService;
import auth.authrestaurantlocator.models.ERole;
import auth.authrestaurantlocator.models.Token;
import auth.authrestaurantlocator.models.TokenType;
import auth.authrestaurantlocator.models.User;
import auth.authrestaurantlocator.payload.AuthenticationResponse;
import auth.authrestaurantlocator.payload.LoginRequest;
import auth.authrestaurantlocator.payload.RegisterRequest;
import auth.authrestaurantlocator.repository.TokenRepository;
import auth.authrestaurantlocator.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.naming.AuthenticationException;
import javax.sql.DataSource;
import java.io.IOException;
import java.net.http.HttpHeaders;
import java.sql.SQLException;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    @Autowired
    DataSource dataSource;


    public AuthenticationResponse authenticate(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("user not found"));

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public ResponseEntity<String> register(RegisterRequest request) {
        try {
            User user = User.builder()
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(ERole.USER)
                    .build();
            userRepository.save(user);
            return ResponseEntity.ok("User registered!");
        } catch (DataIntegrityViolationException e) {
            return ResponseEntity.badRequest().body("Email address already in use");
        }
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId()).orElseThrow(() -> new RuntimeException("no valid tokens found"));

        if (validUserTokens.isEmpty()) {
            return;
        }

        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });

        tokenRepository.saveAll(validUserTokens);
    }

    private void  saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
       tokenRepository.save(token);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.userRepository.findByEmail(userEmail).orElseThrow(() -> new UsernameNotFoundException("email not found"));

            if (jwtService.isTokenValid(refreshToken, user)) {

                var accessToken = jwtService.generateToken(user);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);

            }
        }


    }
}
