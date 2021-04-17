package io.security.basiececurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String indexPage() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user(Authentication authentication) {

        return authentication.getName();
    }

    @GetMapping("/admin/pay")
    public String adminPay(Authentication authentication) {
        return authentication.getName();
    }

    @GetMapping("/admin/**")
    public String admin(Authentication authentication) {

        return authentication.getName();
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

}
