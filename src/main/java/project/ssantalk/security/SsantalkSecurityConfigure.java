package project.ssantalk.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import project.ssantalk.security.component.SecurityProblemSupport;
import project.ssantalk.security.service.AuthenticationConvertFilter;

/**
 * @author dragon
 * @see HttpSecurity
 * @see org.springframework.security.web.DefaultSecurityFilterChain
 * @since 2021. 03. 14.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class SsantalkSecurityConfigure
										extends
											WebSecurityConfigurerAdapter {
	final SecurityProblemSupport problemSupport;

	final AuthenticationConvertFilter convertFilter;

	@Override
	public void configure(WebSecurity web) throws Exception {
		web	.ignoring()
			.antMatchers(	"/resources/**",
							"/monitor/**",
							"/callback/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf()
			.disable()
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.NEVER);

		http.authorizeRequests()
			.requestMatchers(CorsUtils::isPreFlightRequest)
			.permitAll()
			.antMatchers("/auth/login", "/reject", "/auth/token")
			.permitAll()
			.antMatchers(	"/auth/logout",
							"/api/**")
			.authenticated();

		http.cors()
			.configurationSource(corsConfigurationSource());

		http.exceptionHandling()
			.authenticationEntryPoint(problemSupport)
			.accessDeniedHandler(problemSupport);

		http.addFilterAfter(convertFilter.getFilter(),
							SecurityContextPersistenceFilter.class);
	}

	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		// - (3)
		configuration.addAllowedOrigin("*");
		configuration.addAllowedMethod("GET");
		configuration.addAllowedMethod("POST");
		configuration.addAllowedMethod("PUT");
		configuration.addAllowedMethod("DELETE");
		configuration.addAllowedMethod("PATCH");
		configuration.addAllowedMethod("OPTIONS");
		configuration.addAllowedHeader("*");
		configuration.setAllowCredentials(false);
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration(	"/**",
											configuration);
		return source;
	}
}
