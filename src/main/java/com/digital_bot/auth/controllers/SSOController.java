package com.digital_bot.auth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
@RequestMapping("/saml")
public class SSOController {
    private final MetadataManager metadata;

    @Autowired
    public SSOController(MetadataManager metadata) {
        this.metadata = metadata;
    }

    @GetMapping("/idpSelection")
    public String idpSelection(HttpServletRequest request, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && !(authentication instanceof AnonymousAuthenticationToken)) {
            return "redirect:/landing";
        } else {
            if (isForwarded(request)) {
                model.addAttribute("idps", metadata.getIDPEntityNames());
                return "saml/idpselection";
            } else {
                return "redirect:/";
            }
        }
    }

    private boolean isForwarded(HttpServletRequest request) {
        return request.getAttribute("javax.servlet.forward.request_uri") != null;
    }

}
