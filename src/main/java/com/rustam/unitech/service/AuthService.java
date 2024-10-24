package com.rustam.unitech.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.rustam.unitech.dto.request.AuthRequest;
import com.rustam.unitech.dto.request.RefreshRequest;
import com.rustam.unitech.dto.response.AuthResponse;
import com.rustam.unitech.dto.response.TokenPair;
import com.rustam.unitech.dto.response.UserResponse;
import com.rustam.unitech.exception.custom.UserNotFoundException;
import com.rustam.unitech.model.User;
import com.rustam.unitech.repository.UserRepository;
import com.rustam.unitech.service.user.UserDetailsServiceImpl;
import com.rustam.unitech.util.jwt.JwtService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class AuthService {

    UserRepository userRepository;
    UserDetailsServiceImpl userDetailsService;
    JwtService jwtService;
    RedisTemplate<String,String> redisTemplate;

    public AuthResponse login(AuthRequest authRequest) {
        User user = userRepository.findByUsername(authRequest.getUsername())
                .orElseThrow(() -> new UserNotFoundException("User Not Found with username: " + authRequest.getUsername()));
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getId());
        TokenPair tokenPair = userDetails.isEnabled() ?
                TokenPair.builder()
                        .accessToken(jwtService.createToken(user.getId()))
                        .refreshToken(jwtService.createRefreshToken(user.getId()))
                        .build()
                : new TokenPair();  // Boş tokenlər üçün
        String redisKey = "refresh_token:" + user.getId(); // userId istifadəçinin identifikatorudur
        redisTemplate.opsForValue().set(redisKey, tokenPair.getRefreshToken(), Duration.ofSeconds(30)); // 30 gün müddətinə saxla
        return AuthResponse.builder()
                .tokenPair(tokenPair)
                .build();
    }

    public Object refreshToken(RefreshRequest request) {
        System.out.println(request.getRefreshToken());
        String userId = jwtService.getUserIdAsUsernameFromToken(request.getRefreshToken()); // Token-dan user ID-ni çıxart

        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        String redisKey = "refresh_token:" + userId; // Redis açarını yaradın
        String storedRefreshToken = redisTemplate.opsForValue().get(redisKey); // Redis-dən saxlanmış refresh token-i alın

        if (storedRefreshToken != null && storedRefreshToken.equals(request.getRefreshToken())) {
            // Refresh token doğru, yeni access token yarat
            return jwtService.createToken(userId);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
    }
}
