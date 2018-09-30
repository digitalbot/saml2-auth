package com.digital_bot.auth.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LandingController {
    @RequestMapping("/landing")
    public String landing(@AuthenticationPrincipal User user, Model model) {
        model.addAttribute("username", user.getUsername());
        return "landing";
    }
}
