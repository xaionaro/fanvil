package fanvil;

import (
	"io";
	"io/ioutil";
	"os";
	"os/exec";
	"fmt";
	"net";
	"net/http";
	"strings";
	"strconv";
	"github.com/ddliu/go-httpclient";
	"crypto/md5";
	"bufio";
	"regexp";
);

type Fanvil struct {
	addr			string;
	port			string;
	login			string;
	password		string;

	authed			bool;

	telnetConnection	net.Conn;
	httpConnection		*httpclient.HttpClient;
	connectionType		int;

	cookies			[]*http.Cookie;

	url			string;
}

const (
	TELNET_PROMT_LOGIN	string = "Login:";
	TELNET_PROMT_PASSWORD	string = "Password:";
	TELNET_PROMT_CMD	string = "# ";

	DEFAULT_PORT_TELNET	string = "23";
	DEFAULT_PORT_HTTP	string = "80";
	DEFAULT_LOGIN		string = "admin";
	DEFAULT_PASSWORD	string = "admin";
	DEFAULT_GOTO_VALUE	string = "Войти";
	DEFAULT_LANGUAGE	string = "12";

	CONNECTIONTYPE_TELNET	int    = 1;
	CONNECTIONTYPE_HTTP	int    = 2;
	CONNECTIONTYPE_EXTTELNET int   = 3;

	CFGTRANSPORTPROTO_FTP	int    = 2;	// TODO: Check this value
	CFGTRANSPORTPROTO_HTTP	int    = 4;
	
	SCRIPT_HEADER		string = "if printf '#!/usr/bin/expect\n\nset timeout 5\n\nset phoneaddr [lindex $argv 0]\nset login     [lindex $argv 1]\nset passwd    [lindex $argv 2]\n\nspawn telnet $phoneaddr\n\nexpect \"Login:\"\nsend \"$login\r\"\nexpect \"Password:\"\nsend \"$passwd\r\"\nexpect \"# \"\n";
	SCRIPT_FOOTER		string = "\nexpect \"# \"\n' | expect - $@ | grep \"^Error:\"; then exit 1; else exit 0; fi";
);

func New(addr string, login string, password string) (p Fanvil) {
	if (login == "") {
		login    = DEFAULT_LOGIN;
	}
	if (password == "") {
		password = DEFAULT_PASSWORD;
	}

	//phone := Fanvil{addr: addr, connectionType: CONNECTIONTYPE_HTTP, port: DEFAULT_PORT_HTTP, login: login, password: password};
	//phone := Fanvil{addr: addr, connectionType: CONNECTIONTYPE_TELNET, port: DEFAULT_PORT_TELNET, login: login, password: password};
	phone := Fanvil{addr: addr, connectionType: CONNECTIONTYPE_EXTTELNET, port: DEFAULT_PORT_TELNET, login: login, password: password};

	if (phone.connectionType == CONNECTIONTYPE_HTTP) {
		phone.url = "http://"+phone.addr+":"+phone.port+"/";
	}

	return phone;
}

func (p *Fanvil) Destroy() {
}

func (p *Fanvil) connectThroughTelnet() (err error) {
	p.telnetConnection, err = net.Dial("tcp", p.addr+":"+p.port);
	if (err != nil) {
		return fmt.Errorf("connectThroughTelnet(): %s", err.Error());
	}
	reader         := bufio.NewReader(p.telnetConnection);

	// Waiting for the init string
	_,err = reader.ReadString('\u0005');
	if (err != nil) {
		return fmt.Errorf("connectThroughTelnet(): %s", err.Error());
	}

	return nil;
}
func (p *Fanvil) connectThroughHttp() (err error) {
	p.httpConnection = httpclient.NewHttpClient().Defaults(httpclient.Map{
			httpclient.OPT_PROXY: "10.10.71.1:80", // Anti-chunk proxy
	});
	return nil;
}

func (p *Fanvil) Connect() (err error) {
	switch (p.connectionType) {
		case CONNECTIONTYPE_EXTTELNET:
			return nil;
		case CONNECTIONTYPE_TELNET:
			return p.connectThroughTelnet();
		case CONNECTIONTYPE_HTTP:
			return p.connectThroughHttp();
	}

	return fmt.Errorf("Connect(): Unknown connection type: %i", p.connectionType);
}

func (p *Fanvil) authThroughTelnet() (error) {
	reader          := bufio.NewReader(p.telnetConnection);

	// Login:
	loginPromt,err := reader.ReadSlice(':');
	if (err != nil) {
		return fmt.Errorf("authThroughTelnet(): %s", err.Error());
	}
	if (string(loginPromt) != TELNET_PROMT_LOGIN) {
		return fmt.Errorf("authThroughTelnet(): Got unexpected string: \"%s\" (expected login promt: \""+TELNET_PROMT_LOGIN+"\")", loginPromt);
	}
	_, err = fmt.Fprintf(p.telnetConnection, p.login);
	if (err != nil) {
		return fmt.Errorf("authThroughTelnet(): %s", err.Error());
	}

	// Password:
	passwordPromt, err := reader.ReadSlice(':');
	if (err != nil) {
		return fmt.Errorf("authThroughTelnet(): %s", err.Error());
	}
	if (string(passwordPromt) != TELNET_PROMT_PASSWORD) {
		return fmt.Errorf("authThroughTelnet(): Got unexpected string: \"%s\" (expected password promt: \""+TELNET_PROMT_PASSWORD+"\")", passwordPromt);
	}
	_, err  = fmt.Fprintf(p.telnetConnection, p.password+"\n");
	if (err != nil) {
		return fmt.Errorf("authThroughTelnet(): %s", err.Error());
	}

	return nil;
}

func (p *Fanvil) sendHttpGet(parameters map[string]string) (resp *httpclient.Response, err error) {
	if (len(p.cookies) > 0) {
		resp, err = p.httpConnection.WithCookie(p.cookies[0]).Get(p.url, parameters);
	} else {
		resp, err = p.httpConnection.Get(p.url, parameters);
	}

	if (err == nil) {
//		p.cookies = append(p.cookies, resp.Cookies()...);
		p.cookies = resp.Cookies();
	}

	return resp, err;
}

func (p *Fanvil) sendHttpPost(parameters map[string]string) (resp *httpclient.Response, err error) {
	if (len(p.cookies) > 0) {
		resp, err = p.httpConnection.WithCookie(p.cookies[0]).Post(p.url, parameters);
	} else {
		resp, err = p.httpConnection.Post(p.url, parameters);
	}

	if (err == nil) {
//		p.cookies = append(p.cookies, resp.Cookies()...);
		p.cookies = resp.Cookies();
	}

	return resp, err;
}

func (p *Fanvil) httpGet(parameters map[string]string) (body []byte, err error) {
	resp,err := p.sendHttpGet(nil);
	if (err != nil) {
		return nil,fmt.Errorf("httpGet(): p.sendHttpGet(nil): %s", err.Error());
	}
	defer resp.Body.Close()

	body,err = ioutil.ReadAll(resp.Body);
	if ((err != nil) && (err != io.EOF)) {
		return body,fmt.Errorf("httpGet(): resp.ReadAll(): %s", err.Error());
	}

	return body,nil;
}

func (p *Fanvil) httpPost(parameters map[string]string) (body []byte, err error) {
	resp, err := p.sendHttpPost(parameters);
	if (err != nil) {
		return nil,fmt.Errorf("httpPost(): p.sendHttpPost(parameters): %s", err.Error());
	}
	defer resp.Body.Close()

	body,err = ioutil.ReadAll(resp.Body);
	if ((err != nil) && (err != io.EOF)) {
		return body,fmt.Errorf("httpGet(): resp.ReadAll(): %s", err.Error());
	}

	return body,nil;
}

func (p *Fanvil) authThroughHttp() (error) {
	body,err := p.httpGet(nil);
	if (err != nil) {
		return fmt.Errorf("authThroughHttp(): %s", err.Error());
	}

	parameters := make(map[string]string);

	re				:= regexp.MustCompile("name=\"nonce\" value=\"[^\"]{16}\"");
	words				:= strings.Split(re.FindString(string(body)), "\"");
	if (len(words) < 5) {
		return fmt.Errorf("authThroughHttp(): Cannot parse the response");
	}
	parameters["nonce"]		 = words[3];

	parameters["URL"]		 = "/";
	parameters["LOG_Language"]	 = DEFAULT_LANGUAGE;
	parameters["goto"]		 = DEFAULT_GOTO_VALUE;

	// "encode" should be equal: username + ":" + md5(username+":"+password+":"+nonce)
	fmt.Printf("|%v|%v|%v|\n", p.login, p.password, parameters["nonce"]);
	encoded_hash			:= fmt.Sprintf("%x", md5.Sum([]byte(p.login+":"+p.password+":"+parameters["nonce"])));
	parameters["encoded"]		 = p.login+":"+string(encoded_hash);

	body,err			 = p.httpPost(parameters);
	if (err != nil) {
		return fmt.Errorf("authThroughHttp(): %s", err.Error());
	}
	if (strings.Index(string(body), "currentstat.htm") == -1) {
		return fmt.Errorf("authThroughHttp(): Cannot authenticate");
	}
	return nil;
}

func (p *Fanvil) Auth() (error) {
	if (p.authed) {
		return nil;
	}

	if err := p.Connect(); err != nil {
		return err;
	}

	switch (p.connectionType) {
		case CONNECTIONTYPE_EXTTELNET:
			return nil;
		case CONNECTIONTYPE_TELNET:
			return p.authThroughTelnet();
		case CONNECTIONTYPE_HTTP:
			return p.authThroughHttp();
	}

	return fmt.Errorf("Auth(): Unknown connection type: %i", p.connectionType);
}

func (p *Fanvil) setCfgUrlThroughHttp(cfgurl string, proto int) (error) {
	parameters := make(map[string]string);

	// Example: FTP_AutoUser_R=&FTP_AutoPasswd_R=&FTP_AutoConfigEncKey_RW=&FTP_ApCfgEncComKey_RW=&SYS_OptionCustom_R=66&SYS_EnablePnP_RW=ON&SYS_PnPServer_R=224.0.1.75&SYS_PnPPort_R=5060&SYS_PnPTransport_R=0&SYS_PnPInterval_R=1&FTP_AutoServer_R=http%3A%2F%2Fvoip.mephi.ru%2Fphone%2Fconfig%2Ffanvil&FTP_AutoFileName_R=&FTP_ProtocolType=4&FTP_AutoUpdateInterval=1&FTP_AutoDownloadMode=0&SYS_TR069WaringTone_RW=ON&SYS_TR069ServerType_RW=1&SYS_ACSServerURL_RW=0.0.0.0&SYS_ACSUsername_RW=admin&SYS_ACSPassword_RW=admin&SYS_TR069PeriodInterval_RW=3600&CheckBoxManager=SYS_SaveApInfo_RW%2CSYS_EnablePnP_RW%2CSYS_TR069Enable_RW%2CSYS_TR069AutoLogin_RW%2CSYS_TR069WaringTone_RW&DefaultSubmit=%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D0%BD%D0%B8%D1%82%D1%8C
	parameters["FTP_AutoServer_R"]        = cfgurl;
	parameters["FTP_ProtocolType"]        = strconv.Itoa(proto);

	// the rest (sorry for that, preserving of previous values is not implemented, yet):
	parameters["FTP_AutoUser_R"]          = "";
	parameters["FTP_AutoPasswd_R"]        = "";
	parameters["FTP_AutoConfigEncKey_RW"] = "";
	parameters["FTP_ApCfgEncComKey_RW"]   = "";
	parameters["SYS_OptionCustom_R"]      = "66";
	parameters["SYS_EnablePnP_RW"]        = "OFF";
	parameters["SYS_PnPServer_R"]         = "224.0.1.75";
	parameters["SYS_PnPPort_R"]           = "5060";
	parameters["SYS_PnPTransport_R"]      = "0";
	parameters["SYS_PnPInterval_R"]       = "1";
	parameters["FTP_AutoFileName_R"]      = "";
	parameters["FTP_AutoUpdateInterval"]  = "1";
	parameters["FTP_AutoDownloadMode"]    = "0";
	parameters["SYS_TR069WaringTone_RW"]  = "ON";
	parameters["S_TR069ServerType_RW"]    = "1";
	parameters["SYS_ACSServerURL_RW"]     = "0.0.0.0";
	parameters["SYS_ACSUsername_RW"]      = "admin";
	parameters["SYS_ACSPassword_RW"]      = "admin";
	parameters["SYS_TR069PeriodInterval_RW"] = "3600";
	parameters["CheckBoxManager"]         = "SYS_SaveApInfo_RW,SYS_EnablePnP_RW,SYS_TR069Enable_RW,SYS_TR069AutoLogin_RW,SYS_TR069WaringTone_RW";
	parameters["DefaultSubmit"]           = "Применить";

	body,err := p.httpPost(parameters);
	if (err != nil) {
		return fmt.Errorf("setCfgUrlThroughHttp(): %s", err.Error());
	}
	if (strings.Index(string(body), "ShowFrame") == -1) {
		return fmt.Errorf("Cannot set CfgUrl");
	}
	return nil;
}

func (p *Fanvil) SetCfgUrl(cfgurl string, proto int) (error) {
	if err := p.Auth(); err != nil {
		return err;
	}

	switch (p.connectionType) {
		case CONNECTIONTYPE_HTTP:
			return p.setCfgUrlThroughHttp(cfgurl, proto);
	}

	return fmt.Errorf("SetCfgUrl(): Unknown connection type: %i", p.connectionType);
}

func (p *Fanvil) rebootThroughExtTelnet() (error) {
	script := SCRIPT_HEADER + "send \"reload\r\"" + SCRIPT_FOOTER;

	scriptFile,err := ioutil.TempFile("/tmp", "go-fanvil");
	if (err != nil) {
		return fmt.Errorf("downloadCfgThroughExtTelnet(): %s", err.Error());
	}
	defer os.Remove(scriptFile.Name());
	scriptFile.Write([]byte(script));
	scriptFile.Chmod(0700);
	scriptFile.Close();

	cmd := exec.Command("bash", scriptFile.Name(), p.addr, p.login, p.password);
	out,err := cmd.Output();

	if (err != nil) {
		return fmt.Errorf("downloadCfgThroughExtTelnet(): %s: %s", err.Error(), out);
	}

	return nil;
}

func (p *Fanvil) downloadCfgThroughExtTelnet(addr string, file string, user string, password string, proto int) (error) {
	var proto_str string;

	script := SCRIPT_HEADER + "set proto     [lindex $argv 3]\nset addr      [lindex $argv 4]\nset file      [lindex $argv 5]\nset cfglogin  [lindex $argv 6]\nset cfgpasswd [lindex $argv 7]\n" + "send \"download $proto -ip $addr -file $file -user $cfglogin -password $cfgpasswd\r\"" + SCRIPT_FOOTER;

	switch (proto) {
		case CFGTRANSPORTPROTO_FTP:
			proto_str = "ftp";
			if (user == "") {
				user = "anonymous";
			}
			if (password == "") {
				password = "anonymous";
			}
			break;
		default:
			return fmt.Errorf("Unknown protocol id: %i", proto);
	}

	scriptFile,err := ioutil.TempFile("/tmp", "go-fanvil");
	if (err != nil) {
		return fmt.Errorf("downloadCfgThroughExtTelnet(): %s", err.Error());
	}
	defer os.Remove(scriptFile.Name());
	scriptFile.Write([]byte(script));
	scriptFile.Chmod(0700);
	scriptFile.Close();

	//fmt.Printf("%v %v %v %v %v %v %v %v %v %v\n", "bash", scriptFile.Name(), p.addr, p.login, p.password, proto_str, addr, file, user, password);
	cmd := exec.Command("bash", scriptFile.Name(), p.addr, p.login, p.password, proto_str, addr, file, user, password);
	out,err := cmd.Output();

	if (err != nil) {
		return fmt.Errorf("downloadCfgThroughExtTelnet(): %s: %s", err.Error(), out);
	}

	return nil;
}

func (p *Fanvil) downloadCfgThroughTelnet(addr string, file string, user string, password string, proto int) (error) {
	var proto_str string;

	switch (proto) {
		case CFGTRANSPORTPROTO_FTP:
			proto_str = "ftp";
			if (user == "") {
				user = "anonymous";
			}
			if (password == "") {
				password = "anonymous";
			}
			break;
		default:
			return fmt.Errorf("Unknown protocol id: %i", proto);
	}

	// download ftp -ip 10.0.93.2 -file defaultconfig/fanvil/c62.cfg -user anonymous -password anonymous
	cmd := "download "+proto_str+" -ip "+addr+" -file "+file+" -user "+user+" -password "+password;
	_, err := fmt.Fprintf(p.telnetConnection, cmd+"\n");
	if (err != nil) {
		return fmt.Errorf("downloadCfgThroughTelnet(): %s", err.Error());
	}

	return nil;
}

func (p *Fanvil) DownloadCfg(addr string, file string, user string, password string, proto int) (error) {
	if err := p.Auth(); err != nil {
		return err;
	}

	switch (p.connectionType) {
		case CONNECTIONTYPE_EXTTELNET:
			return p.downloadCfgThroughExtTelnet(addr, file, user, password, proto);
		case CONNECTIONTYPE_TELNET:
			return p.downloadCfgThroughTelnet(addr, file, user, password, proto);
	}

	return fmt.Errorf("DownloadCfg(): Unknown connection type: %i", p.connectionType);
}

func (p *Fanvil) Reboot() (error) {
	if err := p.Auth(); err != nil {
		return err;
	}
	switch (p.connectionType) {
		case CONNECTIONTYPE_EXTTELNET:
			return p.rebootThroughExtTelnet();
	}

	return fmt.Errorf("Reboot(): Unknown connection type: %i", p.connectionType);
}

