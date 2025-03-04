# Secure Authentication with Spring Security and Http-Only Cookies

## About
Welcome to tech hub blog post about implementing secure authentication using **Spring Security**, **JWT tokens**, and **Http-Only cookies**. 

This guide is intended for developers looking to enhance the security of their Spring Boot applications using Http-Only cookies for authentication. The full source code for this project can be found [here](https://github.com/memento-tech/spring-security-with-whttp-only-cookie-demo).

## Introduction
Spring Security provides a robust framework for securing Java applications. In this guide, we'll:

- Understand the basics of Spring Security.
- Set up a Spring Boot project with fundamental security configurations.
- Implement authentication using Http-Only cookies and JWT tokens.
- Compare this approach with other security implementations.

## 1. Setting Up a Spring Boot Project

Start by creating a **Spring Boot** project with the following dependencies:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
</dependency>
```

The dependencies listed above will allow us to use Spring Boot starters such as Security and Web. The `jjwt-jackson` dependency is required for handling JWT (JSON Web Token) authentication in Java.

In addition to the dependencies mentioned earlier, we will include the following dependencies to ensure that our application is fully functional and can be properly tested:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <scope>runtime</scope>
</dependency>
```

The dependencies mentioned above will enable us to manage users and create a complete application that we can test to ensure everything functions as expected.

## 2. Basic Spring Security setup

To begin, we will create the SecurityConfig class. In this class, we will configure basic Spring Security. Using the code snippet below, all requests will be permitted by default.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(customizer -> customizer.anyRequest().permitAll())
                .build();
    }
}
```

## 3. Making our project complient with UX standard

Next, to visualize our work, we will create four pages:

-  `index.html` (home page -> This page will be accessible to all users)
-  `login.html` (login form -> This page will be accessible to all users)
-  `ppublic.html` (public page -> This page will be accessible to all users)
-  `secure.html` (secure page -> This page will be accessible only to authenticated users)

These pages will be styled using style.css.

-  `index.html`:

This simple home page will contain three buttons:

-  Try Public Page: This button will navigate to the public page, which is accessible to all users.
-  Try Secured Page: This button will navigate to the secured page, which is only accessible to authenticated users.
-  Go to Login: This button will navigate to the login page, where the user can enter their credentials to log in.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h1>Welcome to Spring Security with HttpOnly Cookie Demo</h1>
    <p>Experience a secure authentication system using Spring Security and HttpOnly cookies.</p>
    <div class="links">
        <a href="/public" class="button">Try Public Page</a>
        <a href="/secured" class="button">Try Secured Page</a>
        <a href="/login" class="button">Go to Login</a>
    </div>
</div>
</body>
</html>
```

-  `login.html`:

The login page will have a form that sends the user data using the POST method. Note that the action is set to `/perform-login`, which is required because we want to leverage Spring's built-in authentication functionality and avoid complicating the project.

When the `submit` button is clicked, the user data will be passed to Spring’s authentication functionality, which will verify the credentials according to the default or provided user authentication method. More on this in the next section.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="login-container">
    <h2>Login</h2>
    <form method="post" action="/perform_login">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required />

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required />

        <button type="submit" class="button">Login</button>
    </form>
</div>
</body>
</html>
```

-  `ppublic.html`: (note the name of the page)

The public page will contain text indicating that this page is accessible to all users, both authenticated and non-authenticated. It will also have a button that takes the user back to the 'home' page.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Public Page</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h2>This is a publicly accessible page</h2>
    <p>No authentication is required to view this page.</p>

    <a href="/" class="button">Home</a>
</div>
</body>
</html>
```

- `secure.html`:

The secure page will be simple, like the others. It will display text indicating that the page is secured and include a `Logout` button. This button will be used to remove the HTTP-only cookie from the browser storage, effectively logging the user out.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secured Page</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<div class="container">
    <h2>This is a secured page</h2>
    <p>Only authenticated users can access this page.</p>
    <form method="post" action="/logout">
        <button type="submit" class="button logout">Logout</button>
    </form>
</div>
</body>
</html>
```

## 3. Updating Spring Boot Application to Serve Views

To serve the pages we created in the previous section, we have two options:

-  The first option is to create dedicated controllers and process each request manually.
-  The second option, since we don’t have any special business logic, is to use Spring’s `ViewControllerRegistry` object, which simplifies the process by automatically handling view mappings.

In this case, we will use `ViewControllerRegistry` to simplify our project. To add a view mapping, we simply call the `addViewController` method, provide the mapping, and set the view name. The view name corresponds to the full file name. If we decide to use Thymeleaf, we won’t need to add the `.html` suffix to the view name.

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("forward:/index.html");
        registry.addViewController("/login").setViewName("forward:/login.html");

        registry.addViewController("/public**").setViewName("forward:/ppublic.html");
        registry.addViewController("/public/**").setViewName("forward:/ppublic.html");

        registry.addViewController("/secured**").setViewName("forward:/secure.html");
        registry.addViewController("/secured/**").setViewName("forward:/secure.html");
    }
}
```
The first two view controllers are straightforward—they map the root (`/`) to `index.html` and the login page (`/login`) to `login.html`. Whenever a user accesses the `/` mapping, Spring will serve the `index.html` page.

The view controllers for `/public**` and `/public/**` handle public page mappings, and similarly, the view controllers for `/secured**` and `/secured/**` manage the secured page mappings. The pattern `**` ensures that any request starting with `/public` or `/secured` is mapped correctly. This approach is primarily used for easier testing of the web pages in the development phase.

**Important note:** This approach should not be used in production-grade applications, as it may lead to unwanted behavior or security issues. For example, in production environments, you would likely want to apply more refined access control to these mappings.

The naming of `ppublic.html` is intentional and helps avoid circular behavior when a user tries to access the `public` page. If we used `public.html`, the controller would enter a loop because each request path starts with public. Using `ppublic.html` helps bypass this issue and ensures that the view mapping works as expected.

## 4. Requierd bean dependencies
Before we start working on JWT tokens and HTTP-only cookies, we will set up some beans that will be used throughout the rest of the project. In the ApplicationConfig class, two beans are added:

-  PasswordEncoder: This bean is used to encode passwords provided by the user. It helps ensure that passwords are securely stored and not kept in plaintext.
-  AuthenticationProvider: This bean will be used by Spring Security to authenticate users. It acts as the intermediary between Spring Security and the application's user authentication logic.
-  UserDetailsService: This service is used by Spring Security to search for users by their username. It provides the necessary user information needed for authentication.

Additionally, we will provide a test user to help us verify the final result.

Test user details:

-  Username: test
-  Password: password

This test user will allow us to check if the authentication process is working as expected before proceeding with further steps.

```java
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails testUser = User.builder()
                .username("test")
                .password(passwordEncoder().encode("password"))
                .build();

        return new InMemoryUserDetailsManager(testUser);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}
```

## 4. Implementing JWT and Http-Only Cookie Authentication

In order to enable JTW Token authentication using HTTP only cookie, we will have to add logic for proccessing both JWT Tokena and HTTP only cookie. We will start with JWT Token:

### **Creating JWTTokenService**

Before diving into the implementation, let’s first understand what a JWT token is, how it is structured, and what it contains.

#### JWT Token Overview

JWT (JSON Web Token) is a compact, URL-safe token that is commonly used for securely transmitting information between parties as a JSON object. It is primarily used in authentication and authorization processes in web applications.

A JWT token consists of three parts:

1.  **Header**: Contains metadata about the token, such as the signing algorithm (e.g., HMAC SHA256 or RSA).
2.  **Payload**: Contains claims, which are user-specific data such as roles, permissions, or other relevant information.
3.  **Signature**: Ensures the token has not been tampered with during transmission.

A JWT is generated by the server after successful authentication. The process works as follows:

-  The server authenticates the user (e.g., via username and password).
-  The server generates a payload with relevant user details (like user ID and roles).
-  The payload is Base64Url-encoded.
-  The server signs the token using a secret key or a private key (for asymmetric encryption).
-  The signed token is then sent back to the client for further authentication.

A JWT token consists of three Base64-encoded sections, separated by dots (.). Here is an example of how it looks:

```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Each section represents:

1.  Header: The header typically consists of the algorithm used for signing the token (`alg`) and the type of token (`typ`), which is usually "JWT". Example:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

2.  Payload (Claims): The payload contains the actual claims. Claims are statements about an entity (usually the user) and additional data. It can contain:

-  Authentication claims:
   -  ub (subject) – The unique identifier for the user.
   -  iat (issued at) – The timestamp when the token was created.
   -  exp (expiration) – The timestamp when the token expires.
   -  aud (audience) – The intended recipient of the token.

-  Authorization claims:
   -  role – The user’s role (e.g., admin, user).
   -  permissions – Specific permissions granted to the user.

-  Custom claims:
   -  email – The user’s email address.
   -  company – The company the user is associated with.

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

3.  Signature:
  The signature ensures that the token has not been tampered with. It is created by taking the encoded header and payload, signing them with a secret key (using the algorithm specified in the header), and generating the final signature.

A JWT token is created and transmitted as follows:

1.  The server authenticates the user, usually via username and password.
2.  A payload is generated with the relevant user information and claims.
3.  The payload is encoded using Base64Url.
4.  The header and payload are signed using a secret key.
5.  The server sends the resulting JWT token back to the client.

### JWT Token Use Cases

JWT tokens are widely used in modern authentication systems due to their stateless nature, meaning that the server does not need to store any session data. Instead, all the information needed for authentication is contained within the token itself. Here are some use cases:

-  Authentication: After logging in, the server issues a JWT token that the client sends with every subsequent request, allowing the server to authenticate the user without needing to check a session.
-  Authorization: JWT tokens can include information about the user's roles and permissions, allowing the server to enforce authorization rules for each endpoint.

### Security Considerations

While JWT tokens offer many advantages, they must be handled carefully to avoid security risks such as:

-  Token leakage: If a JWT token is leaked or stolen, it can be used by an attacker to impersonate the user until the token expires.
-  Weak signing keys: Using weak or easily guessable signing keys can allow an attacker to forge JWT tokens.

To mitigate these risks, it’s crucial to:

-  Use strong secret keys for signing JWT tokens.
-  Store tokens securely (e.g., using HTTP-only cookies to prevent XSS attacks).
-  Set reasonable expiration times and refresh tokens to manage session lifetimes.

### Next Steps: Implementing the JWT Token Service

In the next step, we will implement the JWT token generation logic. We will create a JWTTokenService that will handle:

-  The creation of JWT tokens.
-  The extraction of claims (e.g., user information) from the token.
-  The validation of the token's authenticity and integrity.

This service will play a key role in securing the authentication flow by issuing and validating JWT tokens for user authentication.

### JWT Token Service

The `JwtTokenService` class will contain all necessary methods for token creation, validation, and specific token claim extraction. Below are the methods for creating and validating a JWT token. For the full source code of this service, please refer to the provided implementation.

```java
@Component
public class JwtTokenService {
    private final String SECRET_KEY = "your_secret_key";
    
    private String createToken(Map<String, Object> claims, String username) {
        var expiryDate = new Date(new Date().getTime() + TOKEN_EXPIRY * 1000L);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(Long.MAX_VALUE))
                .setExpiration(expiryDate)
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        if (StringUtils.isBlank(token) || Objects.isNull(userDetails)) {
            return false;
        }

        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

### AccessTokenCookieService

In order to implement HTTP-only cookie authentication, we need a service to process the cookie from each request. This service will be called `AccessTokenCookieService`. The service will include the following logic:

-  Generate HTTP-only cookie using the JWT token created in the JWTTokenService.
-  Extract cookie from request to ensure full control over the cookie name and avoid any potential errors due to typos or inconsistencies.
-  Generate a blank HTTP-only cookie for logging out the user, which ensures that the cookie value is removed from the client's browser.

Below is the full implementation of the AccessTokenCookieService class:

```java
@Service
public class AccessTokenCookieService {

    public Optional<Cookie> getAccessTokenCookie(final HttpServletRequest request) {
        return Arrays.stream(Optional.ofNullable(request.getCookies())
                        .orElse(new Cookie[]{}))
                .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                .findAny();
    }

    public Cookie createHttpOnlyCookie(final String cookieValue) {
        requireNonNull(cookieValue);

        final var cookie = new Cookie(COOKIE_NAME, cookieValue);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(COOKIE_EXPIRY);
        cookie.setPath("/");

        return cookie;
    }

    public Cookie createBlankoHttpOnlyCookie() {
        final var cookie = new Cookie(COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(1);
        cookie.setPath("/");

        return cookie;
    }
}
```
## 5. Security configuration modification

Now that we have all services prepared, we will modify our security configuration class in order to prepare security context for our needs. 

Here is the updated security configuration for your project, including the necessary components and logic to handle JWT token authentication, HTTP-only cookies, session management, and handling unauthenticated users:

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class ApplicationSecurityConfig {

    private static final String[] WHITE_LIST_URL = {
            "/",
            "/index.html",
            "/login",
            "/login.html",
            "/public",
            "/ppublic.html",
            "/styles.css"};

    private final HttpOnlyCookieAuthenticationSuccessHandler httpOnlyCookieAuthenticationSuccessHandler;

    private final HttpOnlyCookieAuthenticationFilter httpOnlyCookieAuthenticationFilter;

    private final AuthenticationProvider authenticationProvider;

    private final CookieClearLogoutHandler cookieClearLogoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .headers(headersConfigurer -> headersConfigurer.frameOptions(Customizer.withDefaults()).disable())
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                        .requestMatchers(WHITE_LIST_URL)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(sessionConfigurer ->
                        sessionConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(httpOnlyCookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(customizer -> customizer
                        .addLogoutHandler(cookieClearLogoutHandler)
                        .logoutSuccessUrl("/")
                        .clearAuthentication(true))
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(httpOnlyCookieAuthenticationSuccessHandler)
                        .permitAll())
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.FOUND.value());
                            response.setHeader("Location", "/login");
                        }))
                .build();
    }
}
```

Explanation of key sections:

-  White Listed URLs: We permit all requests to specific URLs such as `/index.html`, `/login.html`, `/public.html`, and CSS files to ensure they are publicly accessible.
-  Session Management: We use `SessionCreationPolicy.STATELESS` to indicate that the application will not manage sessions, as JWT tokens are used for authentication.
-  JWT Authentication Filter: We add a custom filter (`JwtAuthenticationFilter`) before the `UsernamePasswordAuthenticationFilter` to extract and validate JWT tokens from the HTTP-only cookies in incoming requests.
-  Logout: We define a custom `LogoutHandler` to handle the removal of the JWT cookie upon user logout.
-  Form Login: We specify a custom login page (`/login.html`) and a success handler that generates and sets the JWT token in the HTTP-only cookie once the user successfully logs in.
-  Exception Handling: If an unauthenticated user tries to access a secured page, they are redirected to the login page (`/login.html`).

With this setup, your application is now configured to use JWT token authentication, with HTTP-only cookies, session management, and proper handling of login and logout processes.

## 6. User authentication handler

Now that we have all services prepared for authentication, we can create an AuthenticationSuccessHandler. We will use the `SuccessHandler` because we want to leverage Spring's existing functionality for authentication and only configure the HTTP-only cookie once the user is authenticated.

After the user is authenticated, we will create the HTTP-only cookie using the `AccessTokenCookieService`, with the JWT token generated by the `JwtTokenService`. Finally, we will add the cookie to the response and redirect the user to a secured page.

```java
@Component
@RequiredArgsConstructor
public class HttpOnlyCookieAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenService jwtTokenService;

    private final AccessTokenCookieService accessTokenCookieService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        Cookie authCookie = accessTokenCookieService.createHttpOnlyCookie(jwtTokenService.generateToken(authentication.getName()));

        response.addCookie(authCookie);

        response.sendRedirect("/secured");
    }
}
```

## 7. HttpOnlyCookieAuthenticationFilter

As previously mentioned, since we are using the `STATELESS` session creation policy, we need to inform Spring whether the user is authenticated or not. We can do this by setting the authentication object in the Spring `SecurityContextHolder`.

```java
@Component
@RequiredArgsConstructor
@Slf4j
public class HttpOnlyCookieAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    private final UserDetailsService userDetailsService;

    private final AccessTokenCookieService accessTokenCookieService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (request.getServletPath().startsWith("/secured") && Objects.nonNull(request.getCookies())) {
            Optional<Cookie> accessTokenCookie = accessTokenCookieService.getAccessTokenCookie(request);

            accessTokenCookie.map(Cookie::getValue)
                    .filter(StringUtils::isNotBlank)
                    .ifPresentOrElse(cookieValue -> {
                        var username = jwtTokenService.extractUsername(cookieValue);

                        if (Objects.nonNull(username)) {
                            var authentication = SecurityContextHolder.getContext().getAuthentication();
                            if (Objects.nonNull(authentication)
                                && !authentication.getName().equals(username))
                            {
                                SecurityContextHolder.clearContext();
                            }

                            Optional.ofNullable(userDetailsService.loadUserByUsername(username))
                                    .ifPresentOrElse(userDetails -> {
                                        if (jwtTokenService.validateToken(cookieValue, userDetails)) {
                                            var authToken = new UsernamePasswordAuthenticationToken(
                                                    userDetails,
                                                    null,
                                                    userDetails.getAuthorities()
                                            );
                                            authToken.setDetails(
                                                    new WebAuthenticationDetailsSource().buildDetails(request)
                                            );
                                            SecurityContextHolder.getContext().setAuthentication(authToken);
                                        }
                                    }, () -> {
                                        // user is removed from database or cookie is messed up for some reason, remove cookie data
                                        response.addCookie(accessTokenCookieService.createBlankoHttpOnlyCookie());
                                    });
                        } else {
                            SecurityContextHolder.clearContext();
                        }
                    }, SecurityContextHolder::clearContext);
        }

        filterChain.doFilter(request, response);
    }
}
```

This HttpOnlyCookieAuthenticationFilter is responsible for authenticating users based on the JWT stored in an HTTP-only cookie. Here's a breakdown of its logic:
Key Points in the Logic:

1.  Check if the request is secured:
   -  The filter checks if the request path starts with /secured, meaning it is a secured route that requires authentication.
   -  It also checks if the request contains cookies (request.getCookies()).

2.  Retrieve the authentication cookie:
   -  The accessTokenCookieService.getAccessTokenCookie(request) method is used to find the access_token cookie from the request.
   -  If the cookie exists and is not empty, the code continues; otherwise, it skips further authentication processing.

3.  Extract the JWT Token from the cookie:
   -  If the cookie value is not blank, the JWT token is extracted from it.
   -  The jwtTokenService.extractUsername(cookieValue) method decodes the JWT token and extracts the username claim.

4.  Validate the username:
   -  If a username is found in the JWT, the filter checks if the current authentication is valid:
      -  If there's an existing authentication object (SecurityContextHolder.getContext().getAuthentication()) and the username from the cookie does not match the one in the SecurityContext, it clears the context (SecurityContextHolder.clearContext()).

5.  Load user details and validate the token:
   -  The userDetailsService.loadUserByUsername(username) loads the user details based on the extracted username.
   -  If the user is found, it validates the JWT token by calling jwtTokenService.validateToken(cookieValue, userDetails).
      -  If the token is valid, it creates a new UsernamePasswordAuthenticationToken (which represents the authenticated user) and sets it in the security context (SecurityContextHolder.getContext().setAuthentication(authToken)).
   -  If the token is invalid or the user details are not found (i.e., user removed or cookie messed up), a blank HTTP-only cookie is created using accessTokenCookieService.createBlankoHttpOnlyCookie() to invalidate the session.

6.  Clear the context if the username is not found:
   -  If no username is found in the cookie, it clears the security context (SecurityContextHolder.clearContext()), effectively logging out the user.

7.  Proceed with the filter chain:
   -  After handling authentication or clearing the context, it proceeds with the rest of the filter chain (filterChain.doFilter(request, response)).

Summary:

This filter:

-  Authenticates the user using the JWT token stored in an HTTP-only cookie for requests to secured routes.
-  Validates the token and extracts user details.
-  Sets the authenticated user in the security context if valid, or clears the context if the token is invalid or not present.
-  Clears the cookie if the user is not found in the system or the token is invalid.

## 6. Adding CookieClearLogoutHandler

To log out the user, we need to remove the HTTP-only cookie. Since we do not have direct access to the client browser, one simple approach is to clear the cookie's content. This ensures that the cookie becomes invalid, and our authentication filter will no longer recognize it as a valid authentication cookie.

```java
@Service
public class CookieClearLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (Objects.nonNull(request.getCookies())) {
            Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(COOKIE_NAME))
                    .peek(cookie -> cookie.setValue(""))
                    .forEach(response::addCookie);
        }
    }
}
```

## 7. Comparing Http-Only Cookie Authentication with Other Approaches

### Session-Based Authentication
- **Overview**: Session-based authentication relies on the server storing the session state (typically using a session ID) to keep track of authenticated users. When a user logs in, the server creates a session and returns a session ID that is stored in a cookie on the client-side. On subsequent requests, the client sends this session ID back to the server to maintain the session.
- **Scalability Issues**: Session-based authentication can lead to scalability challenges, particularly in distributed systems or microservices environments. Since the server needs to keep track of all user sessions, it must store session information somewhere, typically in memory or a database. This can create a bottleneck as the number of users grows. Additionally, in cases of horizontal scaling (i.e., multiple application instances), the session data must be shared between instances, which can increase complexity.
- **Security Risks**: Session-based authentication is susceptible to session fixation, session hijacking, and issues related to session expiration management. If a session cookie is hijacked, an attacker can impersonate the user. Moreover, if the session is not properly invalidated upon logout, it could lead to unintended access.

### Bearer Token Authentication (Authorization Header)
- **Overview**: Bearer token authentication is commonly used in APIs, where a JSON Web Token (JWT) is stored in the `Authorization` header of HTTP requests. The token typically contains the user's identity and other claims, and the server verifies the token's signature to authenticate the user.
- **Security Risks**: While bearer token authentication is stateless (which is advantageous for scalability), it can be vulnerable to **Cross-Site Scripting (XSS)** attacks. If the token is stored in `localStorage` or `sessionStorage`, an attacker can potentially steal the token via JavaScript injected into the page. Once the attacker has access to the token, they can impersonate the user. This issue is particularly prominent in Single Page Applications (SPAs), where local storage is often used for token storage. Additionally, bearer tokens can also be susceptible to **Cross-Site Request Forgery (CSRF)** attacks if they are stored in places vulnerable to such attacks.
- **Mitigation Strategies**: To mitigate XSS risks, tokens should be stored in more secure places, such as HTTP-only cookies, or other more advanced mechanisms like encrypted storage. However, when tokens are used in the `Authorization` header, developers need to ensure that proper protections like **CORS (Cross-Origin Resource Sharing)** and token expiration policies are in place.

### Http-Only Cookie Authentication (Our Approach)
- **Overview**: The approach we're using involves storing JWT tokens in **Http-Only cookies**. An HTTP-only cookie is a cookie that cannot be accessed via JavaScript, making it less vulnerable to XSS attacks. The browser automatically includes the cookie in HTTP requests to the server without requiring any explicit handling by the client-side JavaScript.
- **Security Advantages**:
    - **Protection Against XSS Attacks**: Storing JWTs in HTTP-only cookies ensures that the token is not exposed to JavaScript, thus preventing malicious scripts from accessing it and mitigating the risk of XSS attacks.
    - **Automatic Handling by Browsers**: The browser automatically includes the HTTP-only cookie in every HTTP request to the server, eliminating the need for developers to manually attach tokens to headers or manage storage, simplifying client-side code.
    - **CSRF Protection**: With proper implementation, such as using the **SameSite=Strict** cookie attribute and **Secure** flag (which ensures the cookie is only sent over HTTPS), HTTP-only cookies can mitigate the risk of **Cross-Site Request Forgery (CSRF)** attacks. The `SameSite=Strict` setting ensures that cookies are not sent with cross-origin requests, preventing malicious sites from triggering unwanted actions on the authenticated site.
    - **Improved Security**: By utilizing the `Secure` flag, cookies are only sent over HTTPS connections, reducing the risk of man-in-the-middle attacks (MITM) where an attacker could intercept sensitive data in transit.

### Conclusion
In summary, **JWT authentication with Http-Only cookies** offers several security and usability advantages compared to traditional session-based authentication or bearer token authentication:

1. **Mitigation of XSS Attacks**: By storing tokens in HTTP-only cookies, we ensure that the token cannot be accessed via JavaScript, greatly reducing the risk of XSS attacks.
2. **Convenient and Secure Token Management**: The browser automatically handles the inclusion of the HTTP-only cookie in every request, simplifying the authentication flow and improving user experience. The user does not need to manually manage tokens in headers or local storage.
3. **CSRF Protection**: By utilizing the `SameSite=Strict` and `Secure` cookie attributes, this approach mitigates the risk of CSRF attacks, ensuring that cookies are only sent under trusted conditions.
4. **Scalability**: Since the authentication is stateless and handled entirely by JWT, our system is scalable and can handle large volumes of requests efficiently, without the need for server-side session storage.

In conclusion, **JWT authentication with Http-Only cookies** strikes an excellent balance between security and user experience. It addresses common vulnerabilities like XSS and CSRF while streamlining the client-side code for easier management. This approach is highly recommended for modern web applications, especially those using SPAs or requiring enhanced security.

#

Thank you for taking the time to read through this comparison and explanation. I hope this guide has provided valuable insights into the advantages of using JWT authentication with Http-Only cookies, and how it can enhance the security and scalability of your application. If you have any questions, need further clarification, or want to discuss this topic in more detail, don't hesitate to reach out. I'm happy to help and share more knowledge! 😊
