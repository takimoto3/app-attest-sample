package main

import (
	"context"

	"google.golang.org/appengine/log"
)

type AppEngineLogger struct {
	c context.Context
}

func (aelog *AppEngineLogger) SetContext(ctx context.Context) {
	aelog.c = ctx
}

func (aelog *AppEngineLogger) Debugf(format string, args ...interface{}) {
	log.Debugf(aelog.c, format, args...)

}

func (aelog *AppEngineLogger) Infof(format string, args ...interface{}) {
	log.Infof(aelog.c, format, args...)
}

func (aelog *AppEngineLogger) Warningf(format string, args ...interface{}) {
	log.Warningf(aelog.c, format, args...)
}

func (aelog *AppEngineLogger) Errorf(format string, args ...interface{}) {
	log.Errorf(aelog.c, format, args...)
}

func (aelog *AppEngineLogger) Criticalf(format string, args ...interface{}) {
	log.Criticalf(aelog.c, format, args...)
}
