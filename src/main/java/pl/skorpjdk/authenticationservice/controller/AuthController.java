package pl.skorpjdk.authenticationservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.skorpjdk.authenticationservice.dto.UserDto;
import pl.skorpjdk.authenticationservice.model.User;
import pl.skorpjdk.authenticationservice.service.UserService;
import pl.skorpjdk.authenticationservice.util.JwtTokenUtil;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private UserService userService;
    private JwtTokenUtil jwtTokenUtil;

    public AuthController(UserService userService, JwtTokenUtil jwtTokenUtil) {
        this.userService = userService;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody UserDto userDto) {
        User user = userService.register(userDto);
        return ResponseEntity.ok("Użytkownik zarejestrowany: " + user.getUsername());
    }

    @PostMapping("/login")
    public ResponseEntity<String> authenticateUser(@RequestBody UserDto userDto) {
        Optional<User> userOptional = userService.login(userDto.getUsername(), userDto.getPassword());
        if (userOptional.isPresent()) {
            String token = jwtTokenUtil.generateToken(userOptional.get().getUsername());
            return ResponseEntity.ok("Bearer " + token);
        } else {
            return ResponseEntity.status(401).body("Błędne dane logowania");
        }
    }
}
