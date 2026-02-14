package metrics

import (
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	//Request duration histogram with method, endpoint, and status labels
	RequestDuration *prometheus.HistogramVec
	//Login attempts counter
	LoginAttempts *prometheus.CounterVec
	//Total errors counter with error type label
	TotalErrors *prometheus.CounterVec
	//Database query duration histogram with query type and status labels
	DbQueryDuration *prometheus.HistogramVec
	//CPU temperature gauge with core label
	CpuTemp *prometheus.GaugeVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		//Request duration histogram with method, endpoint, and status labels
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "request_duration_seconds",
			Help: "Duration of HTTP requests in seconds."},
			[]string{"method", "endpoint", "status"},
		),
		//Login attempts counter
		LoginAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total number of login attempts.",
		},
			[]string{"status"},
		),
		//Total errors counter with error type label
		TotalErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "total_errors_total",
				Help: "Number of total errors.",
			},
			[]string{"error_type"},
		),
		//Database query duration histogram with query type and status labels
		DbQueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Duration of database queries in seconds.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
		},
			[]string{"query_type", "status"},
		),
		//CPU temperature gauge with core label
		CpuTemp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cpu_temperature_celsius",
			Help: "Current temperature of the CPU.",
		},
			[]string{"core"},
		),
	}
	// Register metrics with the provided registry
	reg.MustRegister(m.RequestDuration)
	reg.MustRegister(m.LoginAttempts)
	reg.MustRegister(m.TotalErrors)
	reg.MustRegister(m.DbQueryDuration)
	reg.MustRegister(m.CpuTemp)
	return m
}

// ObserveDB is a helper method to record the duration and status of database queries in a consistent way.
func (m *Metrics) ObserveDB(queryName string, start time.Time, err error) {
	duration := time.Since(start).Seconds()

	status := "ok"
	if err != nil {
		if err == pgx.ErrNoRows {
			status = "not_found"
		} else {
			status = "error"
		}
	}

	m.DbQueryDuration.WithLabelValues(queryName, status).Observe(duration)
}
