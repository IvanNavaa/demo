package com.example.demo;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;

import javax.sql.DataSource;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.FilesystemResource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
//import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.saml.SamlUserDetailsServiceImpl;

import net.shibboleth.utilities.java.support.xml.ParserPool;



@Configuration
public class SamlSecurityConfig {
	
	 @Value("${JKS_APP}")
	  private String _jksApp;

	  @Value("${JKS_PASS}")
	  private String pwcert;

	  @Value("${URLLOGOUT}")
	  private String urlLogout;

	  @Value("${VARIABLE_WS}")
	  private String rutaConfiguracion;

	  @Value("${PATHJKS}")
	  private String pathJKS;

	  @Value("${PATHIDP}")
	  private String pathIdp;

	  @Value("${SAML.IDP}")
	  private String defaultIdp;

	  @Value("${SAML.SP}")
	  private String samlAudience;

	  @Value("${URL_APP_WS}")
	  private String entityBaseURL;

	  @Value("${APP_NAME}")
	  private String _appName;

	  private JdbcTemplate jdbcToolsnetUsr;

	  @Autowired
	  public void setDatasource(@Qualifier("dsUsuarios") DataSource toolsnetUserDS) {
	  	this.jdbcToolsnetUsr = new JdbcTemplate(toolsnetUserDS);
	  }
	
	  @Bean
	  public SAMLUserDetailsService samlUserDetailsService() {
	    return new SamlUserDetailsServiceImpl(this._appName, jdbcToolsnetUsr);
	  }

	  @Bean
	  public static PropertySourcesPlaceholderConfigurer getPropertySourcesPlaceholderConfigurer() {
	    return new PropertySourcesPlaceholderConfigurer();
	  }

	  @Bean
	  public WebSSOProfileOptions defaultWebSSOProfileOptions() {
	    WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
	    webSSOProfileOptions.setIncludeScoping(false);
	    webSSOProfileOptions.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
	    return webSSOProfileOptions;
	  }

	   @Bean
	    public SAMLEntryPoint samlEntryPoint() {
	        WebSSOProfileOptions options = new WebSSOProfileOptions();
	        options.setIncludeScoping(false);
	        SAMLEntryPoint entryPoint = new SAMLEntryPoint();
	        entryPoint.setDefaultProfileOptions(options);
	        entryPoint.setFilterProcessesUrl("/saml/login");
	        return entryPoint;
	    }

	  @Bean
	  public MetadataDisplayFilter metadataDisplayFilter() {
	    return new MetadataDisplayFilter();
	  }

	  @Bean
	  public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
	    SimpleUrlAuthenticationFailureHandler failureRedirectHandler = new SimpleUrlAuthenticationFailureHandler();
	    failureRedirectHandler.setUseForward(true);
	    failureRedirectHandler.setDefaultFailureUrl("/error");
	    return failureRedirectHandler;
	  }

	  @Bean
	  public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
	    SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	    successRedirectHandler.setAlwaysUseDefaultTargetUrl(true);
	    successRedirectHandler.setDefaultTargetUrl("/auth/access");
	    return successRedirectHandler;
	  }

	  @Bean
	  public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
	    SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
	    samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
	    samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
	    samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());

	    return samlWebSSOProcessingFilter;
	  }

	  @Bean
	  public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
	    SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler();
	    handler.setAlwaysUseDefaultTargetUrl(true);
	    handler.setDefaultTargetUrl(urlLogout);
	    return handler;
	  }

	  @Bean
	  public SecurityContextLogoutHandler logoutHandler() {
	    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
	    logoutHandler.setInvalidateHttpSession(true);
	    logoutHandler.setClearAuthentication(true);
	    return logoutHandler;
	  }

	  @Bean
	  public SAMLLogoutFilter samlLogoutFilter() {
	    return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] {
	        logoutHandler()
	      },
	      new LogoutHandler[] {
	        logoutHandler()
	      });
	  }

	  @Bean
	  public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
	    return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
	  }

	  @Bean
	  public MetadataGeneratorFilter metadataGeneratorFilter() {
	    return new MetadataGeneratorFilter(metadataGenerator());
	  }

	  @Bean
	  public KeyManager keyManager() {
	    DefaultResourceLoader loader = new DefaultResourceLoader();
	    Resource resource = loader.getResource("file:" + rutaConfiguracion + pathJKS);
	    System.out.println("-----------");
	    System.out.println("Se carga JKS " + resource);
	    System.out.println("-----------");
	    String storePass = pwcert;
	    Map < String, String > mapKeys = new HashMap < > ();
	    mapKeys.put(this._jksApp, storePass);
	    return new JKSKeyManager(resource, storePass, mapKeys, this._jksApp);
	  }

	  @Bean
	  @Qualifier("okta")
	  public ExtendedMetadataDelegate oktaExtendedMetadataProvider() throws MetadataProviderException, ResourceException {
	    Timer backgroundTaskTimer = new Timer(true);
	    FilesystemResource metadata = new FilesystemResource(rutaConfiguracion + pathIdp);
	    System.out.println("-----------");
	    System.out.println("Se cargó idp_inicio");
	    System.out.println("-----------");
	    ResourceBackedMetadataProvider resourceBackedMetadataProvider = new ResourceBackedMetadataProvider(
	      backgroundTaskTimer, metadata);
	    resourceBackedMetadataProvider.setParserPool(parserPool());
	    resourceBackedMetadataProvider.setMinRefreshDelay(900000);
	    resourceBackedMetadataProvider.setMaxRefreshDelay(1200000);
	    ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(resourceBackedMetadataProvider,
	      extendedMetadata());
	    extendedMetadataDelegate.setMetadataTrustCheck(false);
	    return extendedMetadataDelegate;
	  }

	  @Bean
	  public ExtendedMetadata extendedMetadata() {
	    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
	    extendedMetadata.setSigningKey(this._jksApp);
	    extendedMetadata.setEncryptionKey(this._jksApp);
	    Set < String > trustedKeys = new HashSet < String > ();
	    trustedKeys.add(this._jksApp);
	    extendedMetadata.setTrustedKeys(trustedKeys);
	    extendedMetadata.setRequireLogoutRequestSigned(true);
	    extendedMetadata.setRequireLogoutResponseSigned(false);
	    extendedMetadata.setIdpDiscoveryEnabled(false);
	    return extendedMetadata;
	  }

	  public MetadataGenerator metadataGenerator() {
	  	System.out.println("-----------");
		  System.out.println("Ingreso a Metadata");
		  System.out.println("-----------");
	    MetadataGenerator metadataGenerator = new MetadataGenerator();
	    metadataGenerator.setEntityId(samlAudience);    
	    metadataGenerator.setExtendedMetadata(extendedMetadata());
	    metadataGenerator.setIncludeDiscoveryExtension(false);
	    metadataGenerator.setKeyManager(keyManager());
	    metadataGenerator.setEntityBaseURL(entityBaseURL);

	    return metadataGenerator;
	  }

	  @Bean
	  public FilterChainProxy samlFilter() throws Exception {
	    List < SecurityFilterChain > chains = new ArrayList < > ();

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
	      metadataDisplayFilter()));

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/**"), samlEntryPoint()));

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
	      samlWebSSOProcessingFilter()));

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
	      samlWebSSOHoKProcessingFilter()));

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));

	    chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
	      samlLogoutProcessingFilter()));

	    return new FilterChainProxy(chains);
	  }

	  @Bean
	  public VelocityEngine velocityEngine() {
	    return VelocityFactory.getEngine();
	  }

	  @Bean(initMethod = "initialize")
	  public StaticBasicParserPool parserPool() {
	    return new StaticBasicParserPool();
	  }

	  @Bean(name = "parserPoolHolder")
	  public ParserPoolHolder parserPoolHolder() {
	    return new ParserPoolHolder();
	  }

	  @Bean
	  public HTTPPostBinding httpPostBinding() {
	    return new HTTPPostBinding(parserPool(), velocityEngine());
	  }

	  @Bean
	  public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
	    return new HTTPRedirectDeflateBinding(parserPool());
	  }

	  @Bean
	  public HTTPSOAP11Binding soapBinding() {
	    return new HTTPSOAP11Binding(parserPool());
	  }

	  private ArtifactResolutionProfile artifactResolutionProfile() {
	    final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
	    artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
	    return artifactResolutionProfile;
	  }

	  @Bean
	  public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
	    return new HTTPArtifactBinding((org.opensaml.xml.parse.ParserPool) parserPool, velocityEngine, artifactResolutionProfile());
	  }

	  @Bean
	  public HTTPPAOS11Binding paosBinding() {
	    return new HTTPPAOS11Binding(parserPool());
	  }

	  @Bean
	  public SAMLProcessorImpl processor() {
	    Collection < SAMLBinding > bindings = new ArrayList < > ();
	    bindings.add(httpRedirectDeflateBinding());
	    bindings.add(httpPostBinding());
	    return new SAMLProcessorImpl(bindings);
	  }

	  @Bean
	  public HttpClient httpClient() {
	    return new HttpClient(multiThreadedHttpConnectionManager());
	  }

	  @Bean
	  public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
	    return new MultiThreadedHttpConnectionManager();
	  }

	  @Bean
	  public static SAMLBootstrap sAMLBootstrap() {
	    return new SAMLBootstrap();
	  }

	  @Bean
	  public SAMLDefaultLogger samlLogger() {
	    SAMLDefaultLogger samlLogger = new SAMLDefaultLogger();
	    samlLogger.setLogErrors(true);
	    samlLogger.setLogMessagesOnException(true);
	    return samlLogger;
	  }

	  @Bean
	  public EmptyStorageFactory emptyStorageFactory() {
	    return new EmptyStorageFactory();
	  }

	  @Bean
	  public SAMLContextProviderImpl contextProvider() {
	    SAMLContextProviderImpl a = new SAMLContextProviderImpl();
	    a.setStorageFactory(emptyStorageFactory());
	    return new SAMLContextProviderImpl();
	  }

	  // SAML 2.0 WebSSO Assertion Consumer
	  @Bean
	  public WebSSOProfileConsumer webSSOprofileConsumer() {
	    return new WebSSOProfileConsumerImpl();
	  }

	  // SAML 2.0 Web SSO profile
	  @Bean
	  public WebSSOProfile webSSOprofile() {
	    return new WebSSOProfileImpl();
	  }

	  // not used but autowired...
	  // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
	  @Bean
	  public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
	    return new WebSSOProfileConsumerHoKImpl();
	  }

	  // not used but autowired...
	  // SAML 2.0 Holder-of-Key Web SSO profile
	  @Bean
	  public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
	    return new WebSSOProfileConsumerHoKImpl();
	  }

	  @Bean
	  public WebSSOProfileECPImpl ecpProfile() {
	    return new WebSSOProfileECPImpl();
	  }

	  @Bean
	  public SingleLogoutProfile logoutprofile() {
	    return new SingleLogoutProfileImpl();
	  }

	  @Bean
	  @Qualifier("metadata")
	  public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException {
	    List < MetadataProvider > providers = new ArrayList < > ();
	    providers.add(oktaExtendedMetadataProvider());
	    CachingMetadataManager metadataManager = new CachingMetadataManager(providers);
	    metadataManager.setDefaultIDP(defaultIdp);
	    return new CachingMetadataManager(providers);
	  }
	 
	  @Bean
	  public SAMLAuthenticationProvider samlAuthenticationProvider() {
	    SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
	    samlAuthenticationProvider.setUserDetails(samlUserDetailsService());
	    samlAuthenticationProvider.setForcePrincipalAsString(false);
	    return samlAuthenticationProvider;
	  }

	  @Bean
		public AuthenticationManager authenticationManager() throws Exception {
	  	 return new ProviderManager(samlAuthenticationProvider());
		}

	  @Bean
	  public HttpSessionEventPublisher httpSessionEventPublisher() {
	    return new HttpSessionEventPublisher();
	  }

	  @Bean
	  public SessionRegistry sessionRegistry() {
	    return new SessionRegistryImpl();
	  }

	  @Bean
	  public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
	    SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
	    samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
	    samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
	    samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
	    return samlWebSSOHoKProcessingFilter;
	  }
	  

	  
	  @Bean
		public SecurityFilterChain filterChain(HttpSecurity http)
		    throws Exception {
			http.csrf(AbstractHttpConfigurer::disable);	
			http.httpBasic(basic -> 			
			basic.authenticationEntryPoint(samlEntryPoint()));	
			http.addFilterAfter(metadataGeneratorFilter(), ChannelProcessingFilter.class)
			.addFilterAfter(samlFilter(),BasicAuthenticationFilter.class);			    
			 http
	     .authorizeHttpRequests(authz -> authz
	         .requestMatchers("/**").permitAll()
	         .anyRequest().authenticated());
			return http.build();
		}
}
