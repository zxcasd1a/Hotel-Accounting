# IdentityService API Gateway Usage Guide

## 1. Overview

This document provides guidance for developers on how to access and use the IdentityService APIs, which are exposed via an AWS API Gateway (HTTP API). The API Gateway serves as the single, secure entry point for all interactions with the IdentityService backend. It handles request routing, authentication via a JWT Lambda Authorizer, rate limiting, and access logging.

## 2. API Gateway Endpoint

All API requests to the IdentityService must be made to the API Gateway endpoint. The specific URL for the deployed API Gateway is an output of the CloudFormation stack used to deploy it.

*   **Placeholder URL:** `https://<api-id>.execute-api.<your-aws-region>.amazonaws.com/<stage-name>`
    *   Replace `<api-id>` with the actual API ID.
    *   Replace `<your-aws-region>` with the AWS region where the API Gateway is deployed (e.g., `us-east-1`).
    *   Replace `<stage-name>` with the deployment stage (e.g., `v1`, `prod`, or `$default` if using the default stage).

    You can find this value in the `ApiEndpoint` output of the `api_gateway_identity_config.yaml` CloudFormation stack.

## 3. Authentication

Most IdentityService API endpoints are protected and require a JSON Web Token (JWT) for authentication.

*   **Authorization Header:** The JWT must be passed in the `Authorization` HTTP header using the Bearer scheme:
    ```
    Authorization: Bearer <YOUR_JWT_TOKEN>
    ```
*   **Obtaining a JWT:**
    *   To obtain a JWT, clients must authenticate through the IdentityService's authentication endpoints, which are also accessed via the API Gateway:
        *   `POST /auth/login`: For primary authentication using email and password.
        *   `POST /auth/login/2fa`: If Two-Factor Authentication (2FA) is enabled for the user, this endpoint is used to submit the 2FA code (TOTP or recovery) after successful primary authentication.
    *   Upon successful completion of the entire authentication flow (including 2FA if enabled), the IdentityService will issue an `accessToken` and a `refreshToken`. The `accessToken` is the JWT to be used for accessing protected endpoints.
*   **Full Authentication Required:** The JWT used must represent a fully authenticated session. This means that if 2FA is enabled for the user account, the 2FA challenge must have been successfully completed during the login process for the token to grant access to protected resources. The Lambda Authorizer will verify the `is_2fa_authenticated: true` claim in the token.

## 4. Available Endpoints

The IdentityService provides a comprehensive set of endpoints for managing identity, authentication, and access control. These are broadly categorized as:

*   **Authentication (`/auth/*`):** Login, 2FA verification, token refresh, logout.
*   **User Management (`/users/me`, `/tenants/{tenantId}/users/*`):** User profile management, user lifecycle operations.
*   **Tenant Management (`/tenants/*`):** Operations for managing tenants.
*   **Role Management (`/roles/system`, `/tenants/{tenantId}/roles/*`, `/roles/{roleId}`):** Managing system and tenant-specific roles.
*   **Permission Management (`/permissions/*`):** Listing and managing granular permissions.
*   **Role-Permission Assignments (`/tenants/{tenantId}/roles/{roleId}/permissions/*`):** Linking permissions to roles.
*   **User-Role Assignments (`/tenants/{tenantId}/users/{userId}/roles/*`):** Assigning roles to users.
*   **2FA Management (`/users/me/2fa/*`):** Endpoints for users to set up, enable, disable, and manage their 2FA settings.

**For a complete and detailed list of all available endpoints, request/response schemas, parameters, and specific functionalities, please refer to the `identity_service_api.yaml` OpenAPI specification.**

## 5. Context Headers (Forwarded to Backend)

For requests to protected endpoints that are successfully authorized, the API Gateway's Lambda Authorizer injects several HTTP headers into the request before forwarding it to the backend IdentityService. These headers provide the backend with the authenticated user's context.

Client-side developers typically do not need to set these headers, but awareness of them can be useful for debugging or if also working on the backend service.

*   `X-User-Id`: The unique identifier (UUID) of the authenticated user.
*   `X-Tenant-Id`: The unique identifier (UUID) of the tenant associated with the user's session (if applicable and present in the token).
*   `X-User-Roles`: A comma-separated string of role names assigned to the user (e.g., "Admin,Editor").
*   `X-User-Permissions`: A comma-separated string of all effective permission names the user possesses through their roles (e.g., "user:create,document:read").
*   `X-Is-2fa-Authenticated`: A string ("true" or "false") indicating if the user's session has completed 2FA.

## 6. Rate Limiting

To ensure fair usage and protect the IdentityService from abuse or overload, rate limits are applied to API requests at the API Gateway level.

*   Clients should be prepared to handle `429 Too Many Requests` HTTP responses.
*   If you receive a `429` error, your client should implement a retry mechanism, preferably with an exponential backoff strategy.
*   The exact rate limits are subject to change and are configured to provide a balance between usability and service protection. Specific limits for authentication routes are more restrictive than general API routes.

## 7. Error Handling

Clients interacting with the API should be prepared to handle standard HTTP error codes:

*   **400 Bad Request:** The request was malformed, contained invalid syntax, or invalid parameters (e.g., missing required fields in the JSON body). The response body may contain more details.
*   **401 Unauthorized:**
    *   The request lacks authentication credentials (e.g., missing `Authorization` header).
    *   The provided JWT is invalid, expired, or malformed.
*   **403 Forbidden:**
    *   The authenticated user does not have the necessary permissions to perform the requested action.
    *   The JWT does not represent a fully authenticated session (e.g., 2FA was required but not completed).
*   **404 Not Found:** The requested resource (e.g., a specific tenant, user, or endpoint path) does not exist.
*   **429 Too Many Requests:** The client has exceeded the allocated rate limits.
*   **5xx Server Error (e.g., 500, 502, 503, 504):** An unexpected error occurred on the server side (either API Gateway or the backend IdentityService).

During development, detailed error messages might be available in API Gateway execution logs or IdentityService application logs. For production, error messages returned to the client will generally be more generic to avoid leaking sensitive information.

## 8. Example Request (Protected Endpoint)

Here's an example using `curl` to access the protected `/users/me` endpoint. Replace `<YOUR_API_GATEWAY_ENDPOINT_URL>` with the actual API Gateway URL and `<YOUR_JWT_TOKEN>` with a valid access token.

```bash
curl -X GET \
  <YOUR_API_GATEWAY_ENDPOINT_URL>/users/me \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: application/json"
```

This request, if successful, will return the profile information of the authenticated user.
