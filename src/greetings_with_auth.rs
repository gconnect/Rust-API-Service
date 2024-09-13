use axum::{
    body::Body, extract::{Path, State}, http::{ HeaderMap, Request, Response, StatusCode}, middleware::from_fn, response::IntoResponse, routing::{delete, get, post, put}, Extension, Json, Router
};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;
use uuid::Uuid;
// use utoipa::{
//   openapi::{self, security::{ ApiKey, ApiKeyValue, SecurityScheme}},
//   Modify, OpenApi,
// };
use utoipa::{openapi::{security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme}, ComponentsBuilder}, Modify, OpenApi};
use utoipa::ToSchema;

use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::Redoc;
use utoipa_scalar::Scalar;
use utoipa_swagger_ui::SwaggerUi;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::middleware::Next;
use tower::ServiceBuilder;

#[derive(OpenApi)]
#[openapi(
  paths(create_greeting, get_greeting, get_all_greetings, update_greeting, delete_greeting, delete_all_greetings, signup, login), 
  components(schemas(Greeting, CreateGreeting, UpdateGreeting, User, AuthResponse, LoginRequest, SignupRequest)),
  security(
    ("BearerAuth" = ["Authorization"]),
),
modifiers(&JwtAuthAddon),
 tags((name="Greeting Rust App", description="This is a sample swagger implementation with axum"),))]
struct ApiDoc;

struct JwtAuthAddon;


impl Modify for JwtAuthAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "BearerAuth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
            )
        }
    }
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
struct Greeting {
    #[schema(example = "4c79ec8b-4b2a-47f3-8f1f-77f0e1cbb493")]
    id: Uuid,
    #[schema(example = "Hello, World!")]
    message: String,   
    #[schema(example = "4c79ec8b-4b2a-47f3-8f1f-77f0e1cbb493")]
    user_id: Uuid,  // Add user_id to the Greeting struct
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
struct GreetingResponse {
    #[schema(example = "Hello, World!")]
    message: String,   
}

#[derive(Deserialize, ToSchema)]
struct CreateGreeting {
    #[schema(example = "Hello, World!")]
    message: String,
}

#[derive(Deserialize, ToSchema)]
struct UpdateGreeting {
    #[schema(example = "Hello, World!")]
    message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct User {
    #[schema(example = "4c79ec8b-4b2a-47f3-8f1f-77f0e1cbb493")]
    id: Uuid,
    #[schema(example = "johndoe")]
    username: String,
    #[schema(example = "password123")]
    password: String, // Store hashed password
}

#[derive(Deserialize, ToSchema)]
struct SignupRequest {
    #[schema(example = "johndoe")]
    username: String,
    #[schema(example = "password123")]
    password: String,
}

#[derive(Deserialize, ToSchema)]
struct LoginRequest {
    #[schema(example = "johndoe")]
    username: String,
    #[schema(example = "password123")]
    password: String,
}

#[derive(Serialize, ToSchema)]
struct AuthResponse {
    #[schema(example = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huZG9lIiwiZXhwIjoxNzI1ODQyMDQ5fQ.PSHexTX21k-PEwuXYRr0qIx2vmrefEQypH0CqhoyFD0")]
    token: String,
}

#[derive(Serialize, ToSchema)]
struct SignupResponse {
    // id: Uuid,
    #[schema(example = "johndoe")]
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid, // user id
    exp: usize,  // Expiration time as Unix timestamp
}
#[derive(Clone)]
struct AuthenticatedUser {
    user_id: Uuid,
}

type DbPool = PgPool;
#[utoipa::path(
    post,
    path = "/signup",
    request_body = SignupRequest,
    responses(
        (status = 201, description = "Greeting created", body = User),
        (status = 400, description = "Invalid input")
    ),
  )]
async fn signup(
    State(pool): State<DbPool>,
    Json(payload): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), StatusCode> {
    // let id = Uuid::new_v4();

    // Hash the password
    let hashed_password = hash(&payload.password, DEFAULT_COST).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Insert user into database
    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        payload.username,
        hashed_password
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(SignupResponse {
                username: payload.username,
            }),
        )),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 201, description = "Greeting created", body = AuthResponse),
        (status = 400, description = "Invalid input")
    ),
  )]
async fn login(
    State(pool): State<DbPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Fetch the user from the database
    let user = sqlx::query_as!(
        User,
        "SELECT id, username, password FROM users WHERE username = $1",
        payload.username
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Verify the password
    let password_matches = verify(&payload.password, &user.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !password_matches {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Create JWT claims
    let expiration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600; // 1 hour
    let claims = Claims {
        sub: user.id.clone(),
        exp: expiration as usize,
    };

    // Generate JWT token
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("secret".as_ref()), // Use a proper secret in production
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AuthResponse { token }))
}

// async fn auth_middleware(req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
//     let auth_header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());

//     if let Some(auth_header) = auth_header {
//         if auth_header.starts_with("Bearer ") {
//             let token = &auth_header[7..]; // Remove "Bearer " from the token string
//             let decoding_key = DecodingKey::from_secret("secret".as_ref()); // Use a proper secret in production
//             let validation = Validation::default();

//             match decode::<Claims>(token, &decoding_key, &validation) {
//                 Ok(_) => {
//                     // Continue with the request if the token is valid
//                     return Ok(next.run(req).await);
//                 }
//                 Err(_) => {
//                     // If token is invalid, return unauthorized
//                     return Err(StatusCode::UNAUTHORIZED);
//                 }
//             }
//         }
//     }

//     // If no valid token, return unauthorized
//     Err(StatusCode::UNAUTHORIZED)
// }

// async fn auth_middleware(mut req: Request<Body>, next: Next) -> Result<Response<Body>, StatusCode> {
//     let auth_header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());

//     if let Some(auth_header) = auth_header {
//         if auth_header.starts_with("Bearer ") {
//             let token = &auth_header[7..]; // Remove "Bearer " from the token string
//             let decoding_key = DecodingKey::from_secret("secret".as_ref()); // Use a proper secret in production
//             let validation = Validation::default();

//             match decode::<Claims>(token, &decoding_key, &validation) {
//                 Ok(token_data) => {
//                     let authenticated_user: AuthenticatedUser = AuthenticatedUser { id: token_data.claims.sub };
//                     req.extensions_mut().insert(authenticated_user);
//                     // Continue with the request if the token is valid
//                     return Ok(next.run(req).await);
//                 }
//                 Err(_) => {
//                     // If token is invalid, return unauthorized
//                     return Err(StatusCode::UNAUTHORIZED);
//                 }
//             }
//         }
//     }

//     // If no valid token, return unauthorized
//     Err(StatusCode::UNAUTHORIZED)
// }

async fn auth_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let auth_header = req.headers().get("Authorization").and_then(|h| h.to_str().ok());

    if let Some(auth_header) = auth_header {
        if auth_header.starts_with("Bearer ") {
            let token = &auth_header[7..]; // Remove "Bearer " from the token string

            let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
            let decoding_key = DecodingKey::from_secret(secret.as_ref());
            let validation = Validation::default();

            match decode::<Claims>(token, &decoding_key, &validation) {
                Ok(token_data) => {
                    let user_id = token_data.claims.sub;
                    let mut req = req;
                    req.extensions_mut().insert(user_id);
                    return Ok(next.run(req).await);
                }
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

// Create greeting handler
#[utoipa::path(
  post,
  path = "/greetings",
  request_body = CreateGreeting,
  responses(
      (status = 201, description = "Greeting created", body = Greeting),
      (status = 400, description = "Invalid input")
  ),
  security(
    ("BearerAuth" = [])
)
)]

async fn create_greeting(
    State(pool): State<DbPool>,
    Json(payload): Json<CreateGreeting>,
    // Extension(user_id): Extension<Uuid>,
) -> Result<impl IntoResponse, StatusCode> {
    // let user_id: Uuid = req.extensions().get().cloned().ok_or(StatusCode::UNAUTHORIZED)?;
    
    let result = sqlx::query!(
        "INSERT INTO greetings (message) VALUES ($1)",
        payload.message,
        // user_id
    )
    .execute(&pool)
    .await;
    // match result {
    //     Ok(_) => Ok((StatusCode::CREATED, Json(GreetingResponse { message: payload.message }))),
    //     Err(err) => {
    //         eprintln!("Error creating greeting: {}", err);
    //         Err(StatusCode::INTERNAL_SERVER_ERROR)
    //     }
    // }
    match result {
        Ok(_) => Ok((StatusCode::CREATED, Json(GreetingResponse { message: payload.message }))),
        Err(err) => {
            eprintln!("Error creating greeting: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Get greeting handler
#[utoipa::path(
  get,
  path = "/greetings/{id}",
  params(("id" = Uuid, description = "Greeting ID")),
  responses(
      (status = 201, description = "Greeting fetched", body = Greeting),
      (status = 404, description = "Greeting not found")
  ),
  security(
    ("BearerAuth" = [])
)
)]
async fn get_greeting(
    State(pool): State<DbPool>,
    Path(id): Path<Uuid>,
) -> Result<Json<Greeting>, StatusCode> {
    let greeting = sqlx::query_as!(
        Greeting,
        "SELECT id, message, user_id FROM greetings WHERE user_id = $1",
        id
    )
    .fetch_one(&pool)
    .await;

    match greeting {
        Ok(greeting) => Ok(Json(greeting)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

// Get all greetings handler
#[utoipa::path(
  get,
  path = "/greetings",
  responses(
      (status = 201, description = "Greetings fetched", body = Json<Vec<Greeting>>),
      (status = 404, description = "Not found")
  ),
  security(
    ("BearerAuth" = [])
)
)]
async fn get_all_greetings(State(pool): State<DbPool>) -> Json<Vec<Greeting>> {
    let greetings = sqlx::query_as!(Greeting, "SELECT id, message, user_id FROM greetings")
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    Json(greetings)
}

// Update greeting handler
#[utoipa::path(
  put,
  path = "/greetings/{id}",
  params( ("id" = Uuid, description = "Greeting ID")),
  request_body = UpdateGreeting,
  responses(
      (status = 201, description = "Greeting created", body = Greeting),
      (status = 400, description = "Invalid input")
  ),
  security(
    ("BearerAuth" = [])
)
)]
async fn update_greeting(
    State(pool): State<DbPool>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateGreeting>,
) -> Result<(StatusCode, Json<Greeting>), StatusCode> {
    let result = sqlx::query!(
        "UPDATE greetings SET message = $2, user_id = $3 WHERE id = $1",
        id,
        payload.message,
        id
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok((
            StatusCode::OK,
            Json(Greeting {
                id,
                message: payload.message,
                user_id: id
            }),
        )),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

// Delete greeting handler
#[utoipa::path(
  delete,
  path = "/greetings/{id}",
  params( ("id" = Uuid, description = "Greeting ID")),
  responses(
      (status = 201, description = "Greeting Deleted", body = Greeting),
      (status = 400, description = "Invalid greeting")
  ),
  security(
    ("BearerAuth" = [])
)
)]
async fn delete_greeting(State(pool): State<DbPool>, Path(id): Path<Uuid>) -> StatusCode {
    let result = sqlx::query!("DELETE FROM greetings WHERE id = $1", id)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

// Delete all greetings handler
#[utoipa::path(
  delete,
  path = "/greetings",
  request_body = Greeting,
  responses(
      (status = 201, description = "Greeting Deleted", body = Greeting),
      (status = 400, description = "Invalid greeting")
  ),
  security(
    ("BearerAuth" = [])
)
)]
async fn delete_all_greetings(State(pool): State<DbPool>) -> StatusCode {
    let result = sqlx::query!("DELETE FROM greetings").execute(&pool).await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[tokio::main]
pub async fn greetings_enpoints() {
    dotenv().ok();


    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    let app = Router::new()
        .route("/", get(|| async { "Hello world!" }))
        .route("/signup",post(signup))
        .route("/login",post(login))
        .route("/greetings",post(create_greeting)
        .layer(from_fn(auth_middleware)))
        .route("/greetings/", get(get_all_greetings).layer(from_fn(auth_middleware)))
        .route("/greetings/", delete(delete_all_greetings).layer(from_fn(auth_middleware)))
        .route("/greetings/:id", get(get_greeting).layer(from_fn(auth_middleware)))
        .route("/greetings/:id", put(update_greeting).layer(from_fn(auth_middleware)))
        .route("/greetings/:id", delete(delete_greeting).layer(from_fn(auth_middleware)))
        // .layer(axum::middleware::from_fn(auth)) // Apply middleware to all routes
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .with_state(pool);

    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Server running at http://{}", addr);

    // Tcp listener
    let listener = TcpListener::bind(addr)
        .await
        .expect("Could not create tcp listener");

    axum::serve(listener, app.into_make_service())
        .await
        .expect("Error serving application");
}
