package core

import (
	"go.uber.org/zap"
)

// Logger ..
var Logger *zap.Logger

// Sugar ..
var Sugar *zap.SugaredLogger

// InitLogger ..
func InitLogger() {
	cfg := zap.NewDevelopmentConfig()

	Logger, _ = cfg.Build()
	Sugar = Logger.Sugar()
}
