package core

import (
	"go.uber.org/zap"
)

var Logger *zap.Logger

var Sugar *zap.SugaredLogger

func InitLogger() {
	cfg := zap.NewDevelopmentConfig()

	Logger, _ = cfg.Build()
	Sugar = Logger.Sugar()
}
