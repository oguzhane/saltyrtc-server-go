package salty

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logging levels
const (
	DebugLevel = 0

	InfoLevel   = 10
	InfoLevel11 = 11 // enable timestamp
	InfoLevel12 = 12 // enable caller
	InfoLevel13 = 13 // enable caller and timestamp

	WarnLevel = 20

	ErrorLevel = 30

	PanicLevel    = 40
	DPanicLevel45 = 45

	FatalLevel = 50
)

// Logger ..
var Logger *zap.Logger

// Sugar ..
var Sugar *zap.SugaredLogger

// InitLogger ..
func InitLogger(level int) {
	loggingLevel := selectLoggingLevel(level)

	isDevelopment := (level < InfoLevel) || (level >= DPanicLevel45 && level < FatalLevel)

	enableTimestamp := true
	enableCaller := true

	if level == InfoLevel {
		enableTimestamp = false
		enableCaller = false
	} else if diff := (level - InfoLevel); diff > 0 && diff < 10 {
		enableCaller = level != InfoLevel11
		enableTimestamp = level != InfoLevel12
	}

	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(loggingLevel),
		Development: isDevelopment,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:       "T",
			LevelKey:      "L",
			NameKey:       "N",
			CallerKey:     "C",
			MessageKey:    "M",
			StacktraceKey: "S",
			LineEnding:    zapcore.DefaultLineEnding,
			EncodeLevel:   zapcore.CapitalLevelEncoder,
			EncodeTime: func() zapcore.TimeEncoder {
				if !enableTimestamp {
					return nil
				}
				return zapcore.ISO8601TimeEncoder
			}(),
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		DisableCaller:    !enableCaller,
	}

	Logger, _ = cfg.Build()
	Sugar = Logger.Sugar()
}

func selectLoggingLevel(level int) zapcore.Level {
	if level < WarnLevel {
		if level < InfoLevel {
			return zap.DebugLevel
		}
		return zap.InfoLevel
	}

	if level < PanicLevel {
		if level < ErrorLevel {
			return zap.WarnLevel
		}
		return zap.ErrorLevel
	}

	if level < DPanicLevel45 {
		return zap.PanicLevel
	} else if level < FatalLevel {
		return zap.DPanicLevel
	}
	return zap.FatalLevel
}
