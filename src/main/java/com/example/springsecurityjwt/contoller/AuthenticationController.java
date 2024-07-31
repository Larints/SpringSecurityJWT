package com.example.springsecurityjwt.contoller;

import com.example.springsecurityjwt.dto.ReqRes;
import com.example.springsecurityjwt.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@RequestMapping("/authentication")
public class AuthenticationController {

    private final AuthService authService;

    @RequestMapping("/signup")
    public ResponseEntity<ReqRes> signUp(@RequestBody ReqRes signUpRequest) {
        return ResponseEntity.ok(authService.signUp(signUpRequest));
    }

    @RequestMapping("signin")
    public ResponseEntity<ReqRes> sigIn(@RequestBody ReqRes sigInRequest) {
        return ResponseEntity.ok(authService.signIn(sigInRequest));
    }

    @RequestMapping("/refresh")
    public ResponseEntity<ReqRes> refreshToken(@RequestBody ReqRes refreshTokenRequest) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
    }
}
