package com.example.springsecurityjwt.configuration;

import com.example.springsecurityjwt.service.OurUserDetailedService;
import lombok.AllArgsConstructor;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final OurUserDetailedService ourUserDetailedService;

    private JwtAuthenticationFilter jwtAuthenticationFilter;


    /**
     * Конфигурирует безопасность приложения, включая настройки для CSRF, CORS и авторизации.
     *
     * @param httpSecurity объект HttpSecurity для настройки безопасности
     * @return объект SecurityFilterChain, который настраивает фильтры и управление сеансом
     * @throws Exception если возникает ошибка при настройке безопасности
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable) // Отключение CSRF защиты
                .cors(Customizer.withDefaults()) // Включение CORS с настройками по умолчанию
                .authorizeHttpRequests(request -> request.requestMatchers("/authentication/**", "/public/**").permitAll()
                        .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")
                        .requestMatchers("/user/**").hasAnyAuthority("USER")
                        .requestMatchers("/adminuser/**").hasAnyAuthority("USER", "ADMIN")
                        .anyRequest().authenticated())
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider()).addFilterBefore( //Установка AuthenticationProvider
                        jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class // Добавление фильтра J
                        // WT аутентификации перед стандартным фильтром аутентификации
                );
        return httpSecurity.build(); // Построение и возврат объекта SecurityFilterChain
    }


    /**
     * Конфигурирует AuthenticationProvider для аутентификации пользователей.
     *
     * @return объект AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(ourUserDetailedService); // Установка сервиса для загрузки пользовательских данных
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); // Установка PasswordEncoder для проверки паролей
        return daoAuthenticationProvider;
    }

    /**
     * Конфигурирует PasswordEncoder для хеширования паролей.
     *
     * @return объект PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Конфигурирует AuthenticationManager для управления аутентификацией.
     *
     * @param authenticationConfiguration конфигурация аутентификации
     * @return объект AuthenticationManager
     * @throws Exception если возникает ошибка при создании AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
