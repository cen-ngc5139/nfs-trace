package config

type Configuration struct {
	Filter     FilterConfig   `yaml:"filter"`
	BTF        BTFConfig      `yaml:"btf"`
	Probing    ProbingConfig  `yaml:"probing"`
	Features   FeaturesConfig `yaml:"features"`
	Output     OutputConfig   `yaml:"output"`
	Logging    LoggingConfig  `yaml:"logging"`
	ConfigPath string         `yaml:"-"`
}

type FilterConfig struct {
	Func   string `yaml:"func"`
	Struct string `yaml:"struct"`
}

type BTFConfig struct {
	Kernel   string `yaml:"kernel"`
	ModelDir string `yaml:"model_dir"`
}

type ProbingConfig struct {
	AllKMods   bool   `yaml:"all_kmods"`
	SkipAttach bool   `yaml:"skip_attach"`
	AddFuncs   string `yaml:"add_funcs"`
}

type FeaturesConfig struct {
	Debug      bool `yaml:"debug"`
	DNS        bool `yaml:"dns"`
	NFSMetrics bool `yaml:"nfs_metrics"`
}

type OutputConfig struct {
	Type          string               `yaml:"type"` // enum: file, stdout, kafka, elasticsearch, logstash, redis
	File          FileOutputConfig     `yaml:"file"`
	Stdout        struct{}             `yaml:"stdout"`
	Kafka         KafkaOutputConfig    `yaml:"kafka"`
	Elasticsearch ESOutputConfig       `yaml:"elasticsearch"`
	Logstash      LogstashOutputConfig `yaml:"logstash"`
	Redis         RedisOutputConfig    `yaml:"redis"`
}

type FileOutputConfig struct {
	Path string `yaml:"path"`
}

type KafkaOutputConfig struct {
	Brokers []string `yaml:"brokers"`
	Topic   string   `yaml:"topic"`
}

type ESOutputConfig struct {
	Hosts []string `yaml:"hosts"`
	Index string   `yaml:"index"`
}

type LogstashOutputConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type RedisOutputConfig struct {
	Addr string `yaml:"addr"`
	Key  string `yaml:"key"`
}

type LoggingConfig struct {
	ToStderr     bool   `yaml:"to_stderr"`
	AlsoToStderr bool   `yaml:"also_to_stderr"`
	File         string `yaml:"file"`
}
