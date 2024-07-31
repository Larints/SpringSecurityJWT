package com.example.springsecurityjwt.configuration;

import com.example.springsecurityjwt.jwt.JWTUtils;
import com.example.springsecurityjwt.service.OurUserDetailedService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;

    private OurUserDetailedService ourUserDetailedService;

    // Метод, выполняемый для каждого HTTP запроса
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Шаг 1: Извлечение заголовка авторизации из запроса
        final String authHeader = request.getHeader("Authorization");
        final  String jwtToken;
        final String userEmail;

        // Шаг 2: Проверка наличия заголовка авторизации
        if (authHeader == null || authHeader.isBlank()) {
            // Если заголовок отсутствует или пуст, пропускаем фильтрацию и передаем запрос дальше
            filterChain.doFilter(request, response);
            return;
        }

        // Шаг 3: Извлечение токена из заголовка
        jwtToken = authHeader.substring(7); // Предполагается, что заголовок начинается с "Bearer" (7 символов)

        // Шаг 4: Извлечение имени пользователя из JWT токена
        userEmail = jwtUtils.extractUsername(jwtToken);

        // Шаг 5: Проверка валидности токена и аутентификации
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Загрузка пользовательских данных с использованием сервиса
            UserDetails userDetails = ourUserDetailedService.loadUserByUsername(userEmail);

            // Проверка, что токен действителен для загруженного пользователя
            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {
                // Шаг 6: Создание нового контекста безопасности
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                // Создание объекта аутентификации для текущего пользователя
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                // Установка деталей аутентификации, включая информацию о запросе
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // Установка аутентификации в контексте безопасности
                securityContext.setAuthentication(token);
                // Установка контекста безопасности в SecurityContextHolder
                SecurityContextHolder.setContext(securityContext);
            }
        }
        // Шаг 7: Передача запроса на дальнейшую обработку в фильтрующий цепочке
        filterChain.doFilter(request, response);
    }

}