package com.digital_bot.auth.services.security;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service("saml2UserDetailsService")
public class SAML2UserDetailsService implements SAMLUserDetailsService {
    @Override
    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        String userId = credential.getNameID().getValue();
        return new User("kosuke", "", true, true, true, true, AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
    }
}
