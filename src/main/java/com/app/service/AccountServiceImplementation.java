package com.app.service;

import com.app.dao.AppRoleRepository;
import com.app.dao.AppUserRepository;
import com.app.entities.AppRole;
import com.app.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
public class AccountServiceImplementation implements  AccountService{
    private AppRoleRepository appRoleRepository ;
    private AppUserRepository appUserRepository ;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder ;

    public AccountServiceImplementation(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository) {
        this.appRoleRepository = appRoleRepository;
        this.appUserRepository = appUserRepository;
    }

    @Override
    public AppUser saveUser(String username, String password, String confirmedPassword) {
        AppUser appUser = appUserRepository.findByUsername(username) ;
        if (appUser != null) throw  new  RuntimeException("User Already exist !");
        if (!password.equals(confirmedPassword)) throw  new RuntimeException("Please confirm new passWord");
        AppUser  appUser1 = new AppUser();
        appUser1.setUsername(username);
        appUser1.setActivated(true);
        appUser1.setPassword(bCryptPasswordEncoder.encode(password));
        appUserRepository.save(appUser1);
        addRoleToUser(username, "USER");
        return appUser1;
    }

    @Override
    public AppRole saveRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findByroleName(rolename);
        appUser.getAppRoles().add(appRole);
    }
}
