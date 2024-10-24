package com.rustam.unitech.controller;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.rustam.unitech.dto.request.AuthRequest;
import com.rustam.unitech.dto.request.RefreshRequest;
import com.rustam.unitech.dto.response.AuthResponse;
import com.rustam.unitech.service.AuthService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping(path = "/api/v1/auth")
@RequiredArgsConstructor
@FieldDefaults(makeFinal = true,level = AccessLevel.PRIVATE)
public class AuthController {

    AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest authRequest){
        return new ResponseEntity<>(authService.login(authRequest), HttpStatus.OK);
    }

    @PostMapping(path = "/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshRequest refreshRequest){
        return new ResponseEntity<>(authService.refreshToken(refreshRequest),HttpStatus.OK);
    }

    @DeleteMapping("/logout")
    public String logout(){
        return "logout";
    }

}
