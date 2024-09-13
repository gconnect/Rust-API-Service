use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use uuid::Uuid;
// use utoipa::{
//   openapi::{self, security::{ ApiKey, ApiKeyValue, SecurityScheme}},
//   Modify, OpenApi,
// };
use utoipa::OpenApi;
use utoipa::ToSchema;

use utoipa_rapidoc::RapiDoc;
use utoipa_redoc::Redoc;
use utoipa_scalar::Scalar;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
  paths(create_greeting, get_greeting, get_all_greetings, update_greeting, delete_greeting, delete_all_greetings), 
  components(schemas(Greeting, CreateGreeting, UpdateGreeting)),
 tags((name="Greeting Rust App", description="This is a sample swagger implementation with axum"),))]
struct ApiDoc;

#[derive(Serialize, Deserialize, Clone, ToSchema)]
struct Greeting {
    #[schema(example = "4c79ec8b-4b2a-47f3-8f1f-77f0e1cbb493")]
    id: Uuid,
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

type DbPool = PgPool;

// Create greeting handler
#[utoipa::path(
  post,
  path = "greetings",
  request_body = CreateGreeting,
  responses(
      (status = 201, description = "Greeting created", body = Greeting),
      (status = 400, description = "Invalid input")
  )
)]
async fn create_greeting(
    State(pool): State<DbPool>,
    Json(payload): Json<CreateGreeting>,
) -> Result<(StatusCode, Json<Greeting>), StatusCode> {
    let id = Uuid::new_v4();
    let result = sqlx::query!(
        "INSERT INTO greetings (id, message) VALUES ($1, $2)",
        id,
        payload.message
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(Greeting {
                id,
                message: payload.message,
            }),
        )),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Get greeting handler
#[utoipa::path(
  get,
  path = "greetings/{id}",
  params(("id" = Uuid, description = "Greeting ID")),
  responses(
      (status = 201, description = "Greeting fetched", body = Greeting),
      (status = 404, description = "Greeting not found")
  )
)]
async fn get_greeting(
    State(pool): State<DbPool>,
    Path(id): Path<Uuid>,
) -> Result<Json<Greeting>, StatusCode> {
    let greeting = sqlx::query_as!(
        Greeting,
        "SELECT id, message FROM greetings WHERE id = $1",
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
  path = "greetings",
  responses(
      (status = 201, description = "Greetings fetched", body = Json<Vec<Greeting>>),
      (status = 404, description = "Not found")
  )
)]
async fn get_all_greetings(State(pool): State<DbPool>) -> Json<Vec<Greeting>> {
    let greetings = sqlx::query_as!(Greeting, "SELECT id, message FROM greetings")
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

    Json(greetings)
}

// Update greeting handler
#[utoipa::path(
  put,
  path = "greetings/{id}",
  params( ("id" = Uuid, description = "Greeting ID")),
  request_body = UpdateGreeting,
  responses(
      (status = 201, description = "Greeting created", body = Greeting),
      (status = 400, description = "Invalid input")
  )
)]
async fn update_greeting(
    State(pool): State<DbPool>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateGreeting>,
) -> Result<(StatusCode, Json<Greeting>), StatusCode> {
    let result = sqlx::query!(
        "UPDATE greetings SET message = $1 WHERE id = $2",
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
            }),
        )),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

// Delete greeting handler
#[utoipa::path(
  delete,
  path = "greetings/{id}",
  params( ("id" = Uuid, description = "Greeting ID")),
  responses(
      (status = 201, description = "Greeting Deleted", body = Greeting),
      (status = 400, description = "Invalid greeting")
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
  path = "greetings",
  request_body = Greeting,
  responses(
      (status = 201, description = "Greeting Deleted", body = Greeting),
      (status = 400, description = "Invalid greeting")
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
pub async fn greetings_api() {
    dotenv().ok();


    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    let app = Router::new()
        .route("/", get(|| async { "Hello world!" }))
        .route("/greetings",post(create_greeting))
        .route("/greetings/", get(get_all_greetings))
        .route("/greetings/", delete(delete_all_greetings))
        .route("/greetings/:id", get(get_greeting))
        .route("/greetings/:id", put(update_greeting))
        .route("/greetings/:id", delete(delete_greeting))
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
