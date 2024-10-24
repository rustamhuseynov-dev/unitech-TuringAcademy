package com.rustam.unitech.service;

import com.rustam.unitech.dto.request.AuthRequest;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class AuthService {

    UserRepository userRepository;
    UserDetailsServiceImpl userDetailsService;
    JwtService jwtService;

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

        return AuthResponse.builder()
                .tokenPair(tokenPair)
                .build();
    }
}
