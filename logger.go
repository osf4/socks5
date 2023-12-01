package socks5

import (
	"os"

	"github.com/gookit/slog"
)

// Logger represents an interface for server loggers
type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
	ErrorT(err error)
}

func defaultLogger() Logger {
	logger := slog.NewSugaredLogger(os.Stdout, slog.DebugLevel)

	f := slog.AsTextFormatter(logger.Formatter)
	f.SetTemplate("[{{datetime}}] {{level}} {{message}}")
	f.EnableColor = true

	return logger
}

// switchLogger represents the logger that could be enabled/disabled
type switchLogger struct {
	Enable bool
	Logger Logger
}

func (l *switchLogger) Infof(format string, args ...any) {
	if l.Enable {
		l.Logger.Infof(format, args...)
	}
}

func (l *switchLogger) Errorf(format string, args ...any) {
	if l.Enable {
		l.Logger.Errorf(format, args...)
	}
}

func (l *switchLogger) ErrorT(err error) {
	if l.Enable {
		l.Logger.ErrorT(err)
	}
}
