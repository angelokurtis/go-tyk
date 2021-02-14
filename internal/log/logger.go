package log

import (
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var l = logrus.New()

func init() {
	l := logrus.New()

	formatter := new(prefixed.TextFormatter)
	formatter.TimestampFormat = `2006-01-02 15:04:05 -0700`
	formatter.FullTimestamp = true

	l.Formatter = formatter
}

func SetLevel(level logrus.Level) {
	l.Level = level
}

func WithPrefix(prefix string) *logrus.Entry {
	return l.WithField("prefix", prefix)
}
