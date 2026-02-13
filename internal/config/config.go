package config

import (
	"flag"
	"os"
	"strconv"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env               string `yaml:"env" default:"development"`
	PostgresConfig    `yaml:"database"`
	JWTConfig         `yaml:"jwt"`
	Server            `yaml:"server"`
	GrpcServer        `yaml:"grpc"`
	RateLimiterConfig `yaml:"rate_limiter"`
	RedisConfig       `yaml:"redis"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr" env:"REDIS_ADDR" env-default:"localhost:6379"`
	Password string `yaml:"password" env:"REDIS_PASSWORD" env-default:""`
	DB       int    `yaml:"db" env:"REDIS_DB" env-default:"0"`
	// Optional: Add fields for connection pool settings, timeouts, etc.
}

type RateLimiterConfig struct {
	Limit  int           `yaml:"limit" env:"RATE_LIMITER_LIMIT" env-default:"100"`
	Window time.Duration `yaml:"window" env:"RATE_LIMITER_WINDOW" env-default:"1m"`
}

type Server struct {
	Port        int           `yaml:"port" env:"SERVER_PORT" env-default:"8082"`
	Mode        string        `yaml:"mode" env:"SERVER_MODE" env-default:"debug"`
	Host        string        `yaml:"host" env:"SERVER_HOST" env-default:"localhost"`
	Timeout     time.Duration `yaml:"timeout" env:"SERVER_TIMEOUT" env-default:"15"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env:"SERVER_IDLE_TIMEOUT" env-default:"60"`
}

type GrpcServer struct {
	Host string `yaml:"host" env:"GRPC_HOST" env-default:"0.0.0.0"`
	Port int    `yaml:"port" env:"GRPC_PORT" env-default:"50052"`
}

type JWTConfig struct {
	Secret            string `yaml:"secret"`
	ExpirationMinutes int    `yaml:"expiration_minutes" default:"15"`
}

// postgres config
type PostgresConfig struct {
	Host     string `yaml:"host" default:"localhost"`
	Port     int    `yaml:"port" default:"5432"`
	Username string `yaml:"username" default:"postgres"`
	Password string `yaml:"password" default:"postgres"`
	Name     string `yaml:"name" default:"myappdb"`
}

func (cfg *PostgresConfig) DSN() string {
	return "postgres://" +
		cfg.Username + ":" +
		cfg.Password + "@" +
		cfg.Host + ":" +
		strconv.Itoa(cfg.Port) + "/" +
		cfg.Name + "?sslmode=disable"
}

// -------------Get Config Path from Flag or Env --------------
var configPath string

func init() {
	flag.StringVar(&configPath, "config", "", "Path to the config file")
}

func fetchConfigPath() string {
	var res string

	if !flag.Parsed() {
		flag.Parse()
	}

	res = configPath

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	if res == "" {
		panic("config path is not provided")
	}

	return res
}
func LoadConfig() Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}
	return LoadConfigFromPath(path)
}

func LoadConfigFromPath(path string) Config {
	var cfg Config
	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic(err)
	}
	return cfg
}
