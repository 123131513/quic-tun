package options

import "github.com/spf13/pflag"

// RestfulAPIOptions contains the options while running a API server.
type RestfulAPIOptions struct {
	HttpdListenOn string `json:"httpd-listen-on" mapstructure:"httpd-listen-on"`
}

func GetDefaultRestfulAPIOptions() *RestfulAPIOptions {
	return &RestfulAPIOptions{
		// zzh: 仿真中修改某一端的监听端口，避免冲突
		// HttpdListenOn: "0.0.0.0:8086",
		HttpdListenOn: "0.0.0.0:8087",
	}
}

// AddFlags adds flags for a specific Server to the specified FlagSet.
func (r *RestfulAPIOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&r.HttpdListenOn, "httpd-listen-on", r.HttpdListenOn,
		"The socket of the API(httpd) server listen on")
}
