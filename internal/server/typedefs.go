package server

type Arguments struct {
	port string
	iface string
	userName string
	passWord string
	hostKeyFile string
	authorizedKeysFile string
	daemon bool
	stop bool
	pidFile string
	logFile string
	addKey string
}
