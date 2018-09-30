package com.digital_bot.auth.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class WebController {
    @RequestMapping("/web/")
    public String index(Model model) {
        model.addAttribute("message", "hello");
        return "/web/index";
    }
}
