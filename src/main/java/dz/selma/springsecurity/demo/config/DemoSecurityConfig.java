package dz.selma.springsecurity.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// add users in memory authentication
		
		@SuppressWarnings("deprecation")
		UserBuilder users = User.withDefaultPasswordEncoder();
		
		auth.inMemoryAuthentication()
		.withUser(users.username("Selma").password("1234").roles("ADMIN", "EMPLOYEE"))
		.withUser(users.username("Hadjer").password("5678").roles("MANAGER", "EMPLOYEE"))
		.withUser(users.username("Islem").password("9012").roles("EMPLOYEE"))
		;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
	//	.anyRequest()
	//	.authenticated()
		.antMatchers("/").hasRole("EMPLOYEE")
		.antMatchers("/leaders/**").hasRole("MANAGER")
		.antMatchers("/systems/**").hasRole("ADMIN")
		.and()
		.formLogin()
		   .loginPage("/showMyLoginPage")
		   .loginProcessingUrl("/authenticateTheUser")
		   .permitAll()
		.and()
		.logout()
		.permitAll()
		.and()
		.exceptionHandling()
		.accessDeniedPage("/access-denied");
	}
}
