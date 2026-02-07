package errorhandler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func HandleError(err error, c echo.Context) {

	code := http.StatusInternalServerError
	message := "Internal Server Error"

	var he *echo.HTTPError
	if errors.As(err, &he) {
		code = he.Code
		message = he.Message.(string)
	}

	if code == http.StatusInternalServerError {
		slog.Error("Internal Server Error",
			"err", err,
			"path", c.Path(),
			"method", c.Request().Method,
		)
	} else {
		slog.Warn("Handled error",
			"err", err,
			"path", c.Path(),
			"method", c.Request().Method,
		)
	}

	if !c.Response().Committed {
		if c.Request().Method == http.MethodHead {
			err = c.NoContent(code)
		} else {
			err = c.JSON(code, map[string]string{"error": message})
		}
	}
}
