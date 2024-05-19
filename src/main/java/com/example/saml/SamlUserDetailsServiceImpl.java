package com.example.saml;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

public class SamlUserDetailsServiceImpl implements SAMLUserDetailsService {
	

  private String _appName;
  private JdbcTemplate jdbcToolsnetUsr;

  public SamlUserDetailsServiceImpl(String pAppName, JdbcTemplate jdbcToolsnetUsr) {
    this._appName = pAppName;
    this.jdbcToolsnetUsr = jdbcToolsnetUsr;
  }

  @Override
  public UserDetails loadUserBySAML(SAMLCredential credential) {
    String noEmpleado = credential.getAttributeAsString("IdEmpleado");
     UserDetails usuario = null;
  
      Set <GrantedAuthority> setAuthorities = new HashSet <GrantedAuthority> ();    
      System.out.println("Authorities: " + setAuthorities);
      List <GrantedAuthority> roles = new ArrayList <GrantedAuthority> (setAuthorities);
      usuario = new SamlUserDetails(credential.getAttributeAsString("IdEmpleado"), "", roles);
    return usuario;
  }

}