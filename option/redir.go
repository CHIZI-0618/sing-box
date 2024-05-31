package option

type RedirectInboundOptions struct {
	ListenOptions
}

type TProxyInboundOptions struct {
	ListenOptions
	AutoTProxy *AutoTProxyOptions `json:"auto_tproxy,omitempty"`
	Network    NetworkList        `json:"network,omitempty"`
}

type AutoTProxyOptions struct {
	Enabled                bool     `json:"enabled,omitempty"`
	ContinueOnNoPermission bool     `json:"continue_on_no_permission,omitempty"`
	ApList                 []string `json:"ap_list,omitempty"`
	IgnoreOutList          []string `json:"ignore_out_list,omitempty"`
	MarkID                 string   `json:"mark_id,omitempty"`
	TableID                string   `json:"table_id,omitempty"`
}
