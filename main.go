package fanvil;

type Fanvil struct {
	addr string;
}

func New(addr string) (p *Fanvil) {
	return &Fanvil{addr: addr};
}

func (p *Fanvil) SetCfgUrl(cfgurl string) (error) {
	return nil;
}

func (p *Fanvil) Reboot( string) (error) {
	return nil;
}

