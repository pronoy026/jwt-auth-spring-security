package com.example.security.jwtauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.jwtauth.Util.JwtUtil;
import com.example.security.jwtauth.model.AuthRequest;
import com.example.security.jwtauth.model.AuthResponse;


@RestController
public class HomeController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@GetMapping("/")
	public String home() {
		return "Welcome To Homepage";
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthToken(@RequestBody AuthRequest authRequest) {
		try {
			//Spring security default authentication attempt
			Authentication authentication = new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword());
			authenticationManager.authenticate(authentication);
			
		} catch (BadCredentialsException e) {
			throw e;
		}
	
		final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
		
		//token generation
		final String jwtToken = jwtUtil.generateToken(userDetails);
		
		AuthResponse response = new AuthResponse(jwtToken);
		
		return ResponseEntity.ok(response);
	}
}
