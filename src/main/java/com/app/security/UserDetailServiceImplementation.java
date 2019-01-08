package com.app.security;

import com.app.entities.AppUser;
import com.app.service.AccountService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserDetailServiceImplementation implements UserDetailsService {
    @Autowired
    private AccountService accountService ;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = accountService.loadUserByUsername(username);
        if (appUser == null)throw new UsernameNotFoundException("Invalid User");
        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        appUser.getAppRoles().forEach( r->{
            grantedAuthorities.add(new SimpleGrantedAuthority(r.getRoleName()));
        });
        return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
    }
}
