# Auth Service 

A robust authentication and session management microservice written in Go. This service provides secure functionality for user registration, login, logout (from a single device or all devices), and token refreshing. It supports communication via both **REST API** and **gRPC**.

## Stack

* **Language:** Go 1.22+
* **Architecture:** Clean Architecture (Repo -> Usecase -> Delivery)
* **REST API:** [Echo](https://echo.labstack.com/)
* **gRPC:** `google.golang.org/grpc`
* **Documentation:** Swagger (`swaggo/swag`)
* **Security:** JWT (Access/Refresh tokens), `golang.org/x/crypto/bcrypt`
* **Metrics:** Prometheus
* **Testing:** `testify`, `gomock` (go.uber.org/mock)

---

## 📁 Project Structure

The project follows Clean Architecture principles for easy scaling and testing:

* `cmd/app/` — Application entry point (`main.go`).
* `domain/entity/` — Core business models (e.g., `Session`, `User`).
* `internal/usecase/` — Business logic (registration, password validation, token handling).
* `internal/delivery/http/` — REST handlers (Echo framework).
* `internal/delivery/grpc/` — gRPC handlers and interceptors (logging, auth, panic recovery).
* `internal/metrics/` — Prometheus metrics collection (e.g., successful/failed login attempts counter).
* `pkg/proto/` — `.proto` contracts and generated gRPC code.

---

## 🛠 Getting Started

### Prerequisites
* [Go](https://golang.org/doc/install) (1.22+)
* [Docker](https://docs.docker.com/get-docker/) and Docker Compose (optional, for infrastructure)
* Swagger CLI: `go install github.com/swaggo/swag/cmd/swag@latest`

### Local Setup

1. Clone the repository:
   ```
   git clone https://github.com/k3rlll/auth.git
   cd auth
   ```
2. Set .env/config files:
   env
   ```
   GOOSE_DRIVER=postgres
   GOOSE_DBSTRING={YOUR_DBSTRING}
   GOOSE_DIR=./migrations
   POSTGRES_PASSWORD={YOUR_POSTGRES_PASSWORD}
   CONFIG_PATH=./configs/config.yaml
   REDIS_ADDR={YOUR_REDIS_ADRESS}
   REDIS_PASSWORD={YOUR_PASSWORD}
   REDIS_DB=0

   JWT_SECRET = "mysecretkey"
   JWT_EXPIRATION_MINUTES = 15
   ```
   config.yaml
   ```
   env: "development"


    server:
      timeout: 15s
      idle_timeout: 60s
      host: "0.0.0.0"
      port: 8082
      server_mode: "development"
    
    rate_limiter:
      limit: 10
      window: 1m
    
    grpc:
      host: 0.0.0.0
      port: 50052
    
    database:
      host: "postgres"
      port: 5432
      username: "postgres"
      name: "myappdb"
   
   ```
3. Build and run app via docker-compose:
Write into terminal
   ```
   task env-build
   task env-run
   ```
