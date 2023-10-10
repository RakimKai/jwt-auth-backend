# Auth_vjezba Backend README

## Overview:
The Auth_vjezba backend is primarily focused on user authentication and authorization. It utilizes Microsoft's ASP.NET Core framework to expose RESTful API endpoints that facilitate user management tasks such as user registration, token generation, token validation, and password hashing.

## Features:

1. **User Registration**:
    - Validates if the provided email or username is already taken.
    - If the provided email and username are unique, it hashes the password using a salt and stores the user in the database.
    - Generates an access token for the newly registered user.

2. **Fetching User Details**:
    - Given an `id`, it returns the user's details if present in the database.

3. **Username and Password Check**:
    - Validates a provided username and password against stored values in the database.
    - If the credentials are valid, an access token is generated and returned.

4. **Token Validation**:
    - Validates a provided JWT token to ensure it's genuine.

## Technical Specifications:

- **Data Context**: Utilizes `ApiContext` for data storage and retrieval operations, which appears to be an Entity Framework Core context.
- **Configuration**: Uses the `IConfiguration` interface from ASP.NET Core to read settings, especially the JWT signing key.
- **Secret Key**: Contains a hardcoded secret key (`SecretKey`) which is used as a symmetric security key for token operations. In a production environment, you'd typically avoid hardcoding and might use secure vaults or configuration management tools.
- **Password Hashing**: Employs the `Rfc2898DeriveBytes` class for hashing passwords using a salt. This provides added security against rainbow table attacks.
- **Token Generation**: Uses the `JwtSecurityToken` class to generate JWT tokens which can be used for authenticating users.

## API Endpoints:

1. **POST /post**: Registers a new user. Returns an access token upon successful registration.
2. **GET /get**: Fetches a user by `id`.
3. **GET /check-username-password**: Validates a username and password, and returns an access token if they are correct.
4. **POST /validate-token**: Validates a provided JWT token.


## Note:
Ensure you keep your `SecretKey` confidential and do not expose it in publicly accessible areas. The above code has a hardcoded secret key, which is not recommended for production. Consider securely managing keys and secrets using tools or services provided by your hosting platform. 
