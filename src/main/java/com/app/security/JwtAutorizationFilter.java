package com.app.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sun.deploy.net.HttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JwtAutorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        httpServletResponse.addHeader("Access-Control-Allow-Origin", "*");
        httpServletResponse.addHeader("Access-Control-Allow-Headers", "Origin, Accept, X-Request-With," +
                "Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, authorization");
        httpServletResponse.addHeader("Access-Control-Expose-Headers", "Access-Control-Allow-Origin," +
                "Access-Control-Credentials, authorization");
        if (httpServletRequest.getRequestURI().equals("OPTIONS")){
            httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        }
        else if (httpServletRequest.getRequestURI().equals("/login")){
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        else {
            String jwtToken = httpServletRequest.getHeader(SecurityParam.JWT_HEADERNAME);
            System.out.print("toke :" + jwtToken);
            if (jwtToken == null || !jwtToken.startsWith(SecurityParam.HEADER_PREFIX)) {
                filterChain.doFilter(httpServletRequest, httpServletResponse);
                return;
            }
            JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(SecurityParam.SECRET)).build();
            String jwt = jwtToken.substring(SecurityParam.HEADER_PREFIX.length());
            DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
            String username = decodedJWT.getSubject();
            List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            roles.forEach(roleName -> {
                grantedAuthorities.add(new SimpleGrantedAuthority(roleName));
            });
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            filterChain.doFilter(httpServletRequest, httpServletResponse);
        }


    }
}
