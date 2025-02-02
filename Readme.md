# User Authentication & OAuth API

## Overview
This API provides endpoints for user authentication, including **registration, login, password management, two-factor authentication (2FA), and OAuth authentication via Google**.

## Features
- **User Registration & OTP Verification**
- **Login with JWT Authentication**
- **Two-Factor Authentication (2FA)**
- **Password Reset & Update**
- **OAuth Authentication with Google**

## Authentication Endpoints

### **1. User Registration**
**Endpoint:**
```
POST /api/v1/auth/register/
```
**Request Body:**
```json
{
    "username": "",
    "email": "",
    "password": "",
    "password_confirmation": ""
}
```

### **2. Verify Registration via OTP**
**Endpoint:**
```
POST /api/v1/auth/verify-email/
```
**Request Body:**
```json
{
    "otp": ""
}
```

### **3. Resend OTP**
**Endpoint:**
```
POST /api/v1/auth/resend-otp/
```
**Request Body:**
```json
{
    "email": ""
}
```

### **4. Login**
**Endpoint:**
```
POST /api/v1/auth/login/
```
**Request Body:**
```json
{
    "email": "",
    "password": ""
}
```

### **5. JWT Refresh Token**
**Endpoint:**
```
POST /api/v1/auth/token/refresh/
```
**Request Body:**
```json
{
    "refresh": ""
}
```

### **6. Reset Password**
**Endpoint:**
```
POST /api/v1/auth/password-reset/
```
**Request Body:**
```json
{
    "email": ""
}
```

### **7. Confirm Password Reset**
**Endpoint:**
```
GET /api/v1/auth/password-reset/confirm/
```
**Response:**
```json
{
    "success": true,
    "message": "valid credentials",
    "uidb64": "encoded_user_id",
    "token": "token"
}
```

### **8. Update Password**
**Endpoint:**
```
PATCH /api/v1/auth/password-reset/update/
```
**Request Body:**
```json
{
    "password": "",
    "confirm_password": "",
    "uidb64": "",
    "token": ""
}
```

### **9. Authentication Test**
**Endpoint:**
```
GET /api/v1/auth/test/
```
**Headers:**
```
Authorization: Bearer <access_token>
```

## OAuth Authentication

### **10. Google OAuth Login**
**Endpoint:**
```
POST /api/v1/auth/google/
```
**Request Body:**
```json
{
    "access_token": ""
}
```

## Response Format
All responses follow this format:
```json
{
    "success": true,
    "message": "description of the response",
    "data": { ... }
}
```

## Authentication Flow
1. **User registers** → Receives OTP → **Verifies OTP**.
2. **User logs in** → Receives JWT token.
3. **User resets password** if forgotten.
4. **Google OAuth** allows users to log in with their Google accounts.
5. **JWT Refresh Token** ensures continued authentication without requiring login again.

## Authorization
For protected routes, include the JWT token in the request headers:
```
Authorization: Bearer <access_token>
```

## Notes
- Ensure you handle **token expiration** and **refreshing tokens** properly.
- OTP verification is required before login.
- OAuth tokens must be validated with Google’s authentication system.

---
**Author:** Al-hassn ebrahiem
**Version:** 1.0  
**Last Updated:** 2025-02-2

