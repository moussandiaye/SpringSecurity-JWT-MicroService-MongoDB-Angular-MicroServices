package com.app.service;

import com.app.entities.AppRole;
import com.app.entities.AppUser;

public interface AccountService {
    public AppUser saveUser(String username, String password, String confirmedPassword);
    public AppRole saveRole(AppRole appRole);
    public AppUser loadUserByUsername(String username);
    public  void addRoleToUser(String username, String rolename);
}
