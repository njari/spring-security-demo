package in.njari.springsecuritydemo.controller;

import in.njari.springsecuritydemo.security.CustomUserDetails;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @RequestMapping(name = "/",method = RequestMethod.GET)
    public String reachedTheAPI() {
        CustomUserDetails principal = (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return "Hey! I know your name is : " + principal.getUsername() + " : and your tagline is : " + principal.getUserTagline();
    }

}
