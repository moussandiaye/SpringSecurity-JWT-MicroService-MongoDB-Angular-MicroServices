package com.app.security;

public interface SecurityParam {
    public static final String JWT_HEADERNAME = "Authorization";
    public static final String SECRET = "moussalmith@gmail.com";
    public static final long EXPIRATION = 864000 ;
    public static final String HEADER_PREFIX = "Bearer ";
}
