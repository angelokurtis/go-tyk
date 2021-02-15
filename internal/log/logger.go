package log

import (
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var logger *logrus.Logger

func init() {
	logger = logrus.New()

	formatter := new(prefixed.TextFormatter)
	formatter.TimestampFormat = `2006-01-02 15:04:05 -0700`
	formatter.FullTimestamp = true

	logger.Formatter = formatter
}

func SetLevel(level logrus.Level) {
	logger.Level = level
}

func WithPrefix(prefix string) *logrus.Entry {
	return logger.WithField("prefix", prefix)
}
