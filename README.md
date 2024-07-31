# spring-oauth2-authorisation-samples

Contains the sample code of Spring Boot Micro Service running with Spring Authorization Server module.

It connects to Mysql DB and registers the clients, saves the authorisation information.

This code depends on following modules

1. Spring Boot 3.2.9
2. spring-boot-starter-oauth2-authorization-server module
3. mysql

This sample code developed using the tutorials from:
<https://docs.spring.io/spring-authorization-server/reference/index.html>
<https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html>

Sample Codes from:
<https://github.com/spring-projects/spring-authorization-server/tree/main/samples/demo-authorizationserver>

Granty Type "password" support:
<https://github.com/eventuate-examples/eventuate-examples-spring-authorization-server>

## Pre-requisites to run this application

1. Java 17
2. MySQL Server 8.X version

## MYSQL Schema and tables creations

### Create Schema

1. Create Schema of your choice
2. Update the application.yml with JDBC connection properties as your schema.

   ```yml
        datasource:
            type: com.zaxxer.hikari.HikariDataSource
            url: jdbc:mysql://localhost:3306/snb_auth?useUnicode=true&characterEncoding=utf8&useSSL=false&&allowPublicKeyRetrieval=true
            username: root
            password: Sidhu@4321
    ```

3. Create Tables

    As per the documentation [Spring Auth Server JPA Link]([https://](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html)), I created following tables

    ```sql
        CREATE TABLE oauth2_authorization (
        id varchar(255) NOT NULL,
        registered_client_id varchar(255) NOT NULL,
        principal_name varchar(255) NOT NULL,
        authorization_grant_type varchar(255) NOT NULL,
        authorized_scopes varchar(1000) DEFAULT NULL,
        attributes text(4000) DEFAULT NULL,
        state varchar(500) DEFAULT NULL,
        authorization_code_value text(4000) DEFAULT NULL,
        authorization_code_issued_at timestamp DEFAULT NULL,
        authorization_code_expires_at timestamp DEFAULT NULL,
        authorization_code_metadata text(2000) DEFAULT NULL,
        access_token_value text(4000) DEFAULT NULL,
        access_token_issued_at timestamp DEFAULT NULL,
        access_token_expires_at timestamp DEFAULT NULL,
        access_token_metadata text(2000) DEFAULT NULL,
        access_token_type varchar(255) DEFAULT NULL,
        access_token_scopes varchar(1000) DEFAULT NULL,
        refresh_token_value text(4000) DEFAULT NULL,
        refresh_token_issued_at timestamp DEFAULT NULL,
        refresh_token_expires_at timestamp DEFAULT NULL,
        refresh_token_metadata text(2000) DEFAULT NULL,
        oidc_id_token_value text(4000) DEFAULT NULL,
        oidc_id_token_issued_at timestamp DEFAULT NULL,
        oidc_id_token_expires_at timestamp DEFAULT NULL,
        oidc_id_token_metadata text(2000) DEFAULT NULL,
        oidc_id_token_claims varchar(2000) DEFAULT NULL,
        user_code_value text(4000) DEFAULT NULL,
        user_code_issued_at timestamp DEFAULT NULL,
        user_code_expires_at timestamp DEFAULT NULL,
        user_code_metadata varchar(2000) DEFAULT NULL,
        device_code_value text(4000) DEFAULT NULL,
        device_code_issued_at timestamp DEFAULT NULL,
        device_code_expires_at timestamp DEFAULT NULL,
        device_code_metadata text(2000) DEFAULT NULL,
        PRIMARY KEY (id)
    );
    ```

    ```sql
    CREATE TABLE oauth2_registered_client (
    id varchar(255) NOT NULL,
    client_id varchar(255) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(255) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(255) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
    );
    ```

    ```sql
    CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(255) NOT NULL,
    principal_name varchar(255) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
    );
    ```

## How to run

Run the applicaiton using Spring Boot Dashboard tools in VSCode/Eclipse.

## Testing

### Testing Client Credentials

- Test client credentials using CURL

    ```sh
    curl --location 'http://localhost:8080/oauth2/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'scope=message.read message.write'
    ```

    You will get Output like below

    ```sh
    {"access_token":"eyJraWQiOiI4M2E0MDA5My1jNzU3LTRjNWUtYmM5Yi03MTlkNDUyY2FmYzkiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsInByaXZpbGVnZXMiOlsiUkVTRU5EX0FDVElWQVRJT05fTElOSyIsIlJFQURfQVVDVElPTiJdLCJuYmYiOjE3MjI0MjM3OTIsInNjb3BlIjpbIm1lc3NhZ2Uud3JpdGUiLCJtZXNzYWdlLnJlYWQiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNzIyNDI0MDkyLCJpYXQiOjE3MjI0MjM3OTIsImp0aSI6IjE2ZTg1MWQ3LWY5NGMtNDM3Ny1iZDJiLTI1NjdlZTEwYWMxNyIsImF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdfQ.tksRiU6kwjTnv4x8dXNFhtldTAlNw_Q0ooOPBOo5Y7cfj3hjrudOwkrpTJ6taBBg_-Hs3cwNCO_x6kZ0lHVk87uTSj8jgol72khtqz4wccP9VvsrFZSE5Xi9Kg9e7UHFpI0q2rKjZbyeJJN4pQjzdWjkP8YXXfBT8zNhz8xQQ7ncxw7opoP0E5gb4nrg_ESHjhMfm_uAW22TdAqcAHDVtL2kyQYRGlxQUoD6-nkc6QWBMoaoTKm7BrqHfCrc4U8bXGymCaKLDOlcuFkmmNcZb7zxz8LHD22472zE67gL3xqc31JO9V3RgiY32NfGsyEwNLKq_n_1X0OiHFVOH2Gc0w","scope":"message.write message.read","token_type":"Bearer","expires_in":299}
    ```

- Test password grant type using CURL
  
    ```sh
    curl --location 'http://localhost:8080/oauth2/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'username=user' \
    --data-urlencode 'password=password' \
    --data-urlencode 'scope=message.read message.write'
    ```

    ## Acknowledgements

    The password grant code is based on the code sample by
    [cer](https://github.com/eventuate-examples/eventuate-examples-spring-authorization-server/commits?author=cer)

