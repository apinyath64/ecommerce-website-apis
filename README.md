# E-commerce API
A compleate backend API for an e-commerce platform build with Node.js Express and Mongodb.
This project provide secure user authentication, items management, cart functionality, delivery address validation and payment intigration with Omise.

This API fully tested by Postman, with detailed documentation included.

## Features
* User Authentication
  * Register and login using JWT-based authentication
  * Password secure hashed using bcrypt
* Item Management
  * Add, update, delete, and view products
* Cart System
    * Add or remove item from shopping cart
    * Update item quantity
    * Retrive user-specific carts
* Delivery Address
    * Save, update and validate addresses using Nominatim API (OpenStreetMap)
* Checkout & Payment
    * Integration with Omise Payment Gateway
* User Profile
    * View and update user information

## Tech Stack
Category | Technology
----|----|
Backend Framwork | Node.js + Express |
Database | MongoDB |
Authentication | JWT (JSON Web Token) |
Password Security | bcrypt |
Payment Gateway | Omise |
Address validation | Nominatim (OpenStreetMap) |
Testing | Postman |
Documentation | Postman API Docs |

## Getting started
### Installing and Setup
  1. Clone the repository
  ```
  git clone https://github.com/yourusername/ecommerce-api.git
  cd ecommerce-api
  ```

  2. Install dependencies
  ```
  npm install
  ```

  3. Configuration environment variables
  Create .env file in the root directory then add required tokens:
  ```
  ACCESS_TOKEN_SECRET=your_access_token
  REFRESH_TOKEN_SECRET=your_refresh_token
  OMISE_PUBLIC_KEY=your_omise_public_key
  OMISE_SECRET_KEY=your_omise_secret_key
  ```
  For your ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET you can create secret token using crypt libraly inside node.js as following example:
  ```
  node
  >> require('crypto').randomBytes(64).toString('hex') 
  ```
  Then using random values for ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET inside .env file

  4. Run the server
  ```
  npm run viewRequest
  ```
  Server will start at:
    http://localhost/4000

## API Documentation
API docementation with request and response examples is available here:
[View Postman API Documentation](https://github.com/apinyath64/ecommerce-website-apis)
