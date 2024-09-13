use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
struct Greeting {
    id: Uuid,
    message: String,
}

#[derive(Deserialize)]
struct CreateGreeting {
    message: String,
}

#[derive(Deserialize)]
struct UpdateGreeting {
    message: String,
}

// App state

type GreetingStore = Arc<Mutex<HashMap<Uuid, Greeting>>>;

// create greeting handler
async fn create_greeting(
    State(store): State<GreetingStore>,
    Json(payload): Json<CreateGreeting>,
) -> Result<(StatusCode, Json<Greeting>), StatusCode> {
    let greeting = Greeting {
        id: Uuid::new_v4(),
        message: payload.message.clone(),
    };

    store.lock().unwrap().insert(greeting.id, greeting.clone());
    Ok((StatusCode::CREATED, Json(greeting)))
}

// get greeting handler
async fn get_greeting(
    State(store): State<GreetingStore>,
    Path(id): Path<Uuid>,
) -> Result<Json<Greeting>, StatusCode> {
    let store = store.lock().unwrap();
    if let Some(greeting) = store.get(&id) {
        Ok(Json(greeting.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// get greeting handler
async fn get_all_greetings(State(store): State<GreetingStore>) -> Json<Vec<Greeting>> {
    let store = store.lock().unwrap();
    let greetings: Vec<Greeting> = store.values().cloned().collect();
    Json(greetings)
}
// Update greeting handler
async fn update_greeting(
    State(store): State<GreetingStore>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateGreeting>,
) -> Result<(StatusCode, Json<Greeting>), StatusCode> {
    let mut store = store.lock().unwrap();
    if let Some(greeting) = store.get_mut(&id) {
        greeting.message = payload.message.clone();
        return Ok((StatusCode::OK, Json(greeting.clone())));
    }
    Err(StatusCode::NOT_FOUND)
}

// Delete greeting handler
async fn delete_greeting(State(store): State<GreetingStore>, Path(id): Path<Uuid>) -> StatusCode {
    let mut store = store.lock().unwrap();
    if store.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// Delete all greetings handler
async fn delete_all_greetings(State(store): State<GreetingStore>) -> StatusCode {
    let mut store = store.lock().unwrap();
    store.clear();
    StatusCode::NO_CONTENT
}
#[tokio::main]
pub async fn make_api_calls() {
    let store: GreetingStore = Arc::new(Mutex::new(HashMap::new()));
    
    // App routes
    let app = Router::new()
        .route("/", get(|| async { "Hello world!" }))
        .route(
            "/greetings",
            post(create_greeting)
                .get(get_all_greetings)
                .delete(delete_all_greetings),
        )
        .route("/greetings/:id", get( get_greeting))
        .route("/greetings/:id", put( update_greeting))
        .route("/greetings/:id", delete(delete_greeting))
        .with_state(store);

    // Address to run the server on
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Server running at http://{}", addr);

    // Tcp listener
    let listener = TcpListener::bind(addr)
        .await
        .expect("Could not create tcp listener");

    // Run server
    axum::serve(listener, app.into_make_service())
        .await
        .expect("Error serving application");
}
