// Code generated by Thrift Compiler (0.21.0). DO NOT EDIT.

package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	thrift "github.com/apache/thrift/lib/go/thrift"
	"github.com/sclgo/impala-go/internal/generated/status"
	"github.com/sclgo/impala-go/internal/generated/beeswax"
	"github.com/sclgo/impala-go/internal/generated/cli_service"
	"github.com/sclgo/impala-go/internal/generated/impalaservice"
)

var _ = status.GoUnusedProtection__
var _ = beeswax.GoUnusedProtection__
var _ = cli_service.GoUnusedProtection__
var _ = impalaservice.GoUnusedProtection__

func Usage() {
	fmt.Fprintln(os.Stderr, "Usage of ", os.Args[0], " [-h host:port] [-u url] [-f[ramed]] function [arg1 [arg2...]]:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nFunctions:")
	fmt.Fprintln(os.Stderr, "  TStatus ResetCatalog()")
	fmt.Fprintln(os.Stderr, "  TOpenSessionResp OpenSession(TOpenSessionReq req)")
	fmt.Fprintln(os.Stderr, "  TCloseSessionResp CloseSession(TCloseSessionReq req)")
	fmt.Fprintln(os.Stderr, "  TGetInfoResp GetInfo(TGetInfoReq req)")
	fmt.Fprintln(os.Stderr, "  TExecuteStatementResp ExecuteStatement(TExecuteStatementReq req)")
	fmt.Fprintln(os.Stderr, "  TGetTypeInfoResp GetTypeInfo(TGetTypeInfoReq req)")
	fmt.Fprintln(os.Stderr, "  TGetCatalogsResp GetCatalogs(TGetCatalogsReq req)")
	fmt.Fprintln(os.Stderr, "  TGetSchemasResp GetSchemas(TGetSchemasReq req)")
	fmt.Fprintln(os.Stderr, "  TGetTablesResp GetTables(TGetTablesReq req)")
	fmt.Fprintln(os.Stderr, "  TGetTableTypesResp GetTableTypes(TGetTableTypesReq req)")
	fmt.Fprintln(os.Stderr, "  TGetColumnsResp GetColumns(TGetColumnsReq req)")
	fmt.Fprintln(os.Stderr, "  TGetFunctionsResp GetFunctions(TGetFunctionsReq req)")
	fmt.Fprintln(os.Stderr, "  TGetOperationStatusResp GetOperationStatus(TGetOperationStatusReq req)")
	fmt.Fprintln(os.Stderr, "  TCancelOperationResp CancelOperation(TCancelOperationReq req)")
	fmt.Fprintln(os.Stderr, "  TCloseOperationResp CloseOperation(TCloseOperationReq req)")
	fmt.Fprintln(os.Stderr, "  TGetResultSetMetadataResp GetResultSetMetadata(TGetResultSetMetadataReq req)")
	fmt.Fprintln(os.Stderr, "  TFetchResultsResp FetchResults(TFetchResultsReq req)")
	fmt.Fprintln(os.Stderr, "  TGetDelegationTokenResp GetDelegationToken(TGetDelegationTokenReq req)")
	fmt.Fprintln(os.Stderr, "  TCancelDelegationTokenResp CancelDelegationToken(TCancelDelegationTokenReq req)")
	fmt.Fprintln(os.Stderr, "  TRenewDelegationTokenResp RenewDelegationToken(TRenewDelegationTokenReq req)")
	fmt.Fprintln(os.Stderr, "  TGetLogResp GetLog(TGetLogReq req)")
	fmt.Fprintln(os.Stderr)
	os.Exit(0)
}

type httpHeaders map[string]string

func (h httpHeaders) String() string {
	var m map[string]string = h
	return fmt.Sprintf("%s", m)
}

func (h httpHeaders) Set(value string) error {
	parts := strings.Split(value, ": ")
	if len(parts) != 2 {
		return fmt.Errorf("header should be of format 'Key: Value'")
	}
	h[parts[0]] = parts[1]
	return nil
}

func main() {
	flag.Usage = Usage
	var host string
	var port int
	var protocol string
	var urlString string
	var framed bool
	var useHttp bool
	headers := make(httpHeaders)
	var parsedUrl *url.URL
	var trans thrift.TTransport
	_ = strconv.Atoi
	_ = math.Abs
	flag.Usage = Usage
	flag.StringVar(&host, "h", "localhost", "Specify host and port")
	flag.IntVar(&port, "p", 9090, "Specify port")
	flag.StringVar(&protocol, "P", "binary", "Specify the protocol (binary, compact, simplejson, json)")
	flag.StringVar(&urlString, "u", "", "Specify the url")
	flag.BoolVar(&framed, "framed", false, "Use framed transport")
	flag.BoolVar(&useHttp, "http", false, "Use http")
	flag.Var(headers, "H", "Headers to set on the http(s) request (e.g. -H \"Key: Value\")")
	flag.Parse()
	
	if len(urlString) > 0 {
		var err error
		parsedUrl, err = url.Parse(urlString)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing URL: ", err)
			flag.Usage()
		}
		host = parsedUrl.Host
		useHttp = len(parsedUrl.Scheme) <= 0 || parsedUrl.Scheme == "http" || parsedUrl.Scheme == "https"
	} else if useHttp {
		_, err := url.Parse(fmt.Sprint("http://", host, ":", port))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error parsing URL: ", err)
			flag.Usage()
		}
	}
	
	cmd := flag.Arg(0)
	var err error
	var cfg *thrift.TConfiguration = nil
	if useHttp {
		trans, err = thrift.NewTHttpClient(parsedUrl.String())
		if len(headers) > 0 {
			httptrans := trans.(*thrift.THttpClient)
			for key, value := range headers {
				httptrans.SetHeader(key, value)
			}
		}
	} else {
		portStr := fmt.Sprint(port)
		if strings.Contains(host, ":") {
			host, portStr, err = net.SplitHostPort(host)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error with host:", err)
				os.Exit(1)
			}
		}
		trans = thrift.NewTSocketConf(net.JoinHostPort(host, portStr), cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error resolving address:", err)
			os.Exit(1)
		}
		if framed {
			trans = thrift.NewTFramedTransportConf(trans, cfg)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating transport", err)
		os.Exit(1)
	}
	defer trans.Close()
	var protocolFactory thrift.TProtocolFactory
	switch protocol {
	case "compact":
		protocolFactory = thrift.NewTCompactProtocolFactoryConf(cfg)
	case "simplejson":
		protocolFactory = thrift.NewTSimpleJSONProtocolFactoryConf(cfg)
	case "json":
		protocolFactory = thrift.NewTJSONProtocolFactory()
	case "binary", "":
		protocolFactory = thrift.NewTBinaryProtocolFactoryConf(cfg)
	default:
		fmt.Fprintln(os.Stderr, "Invalid protocol specified: ", protocol)
		Usage()
		os.Exit(1)
	}
	iprot := protocolFactory.GetProtocol(trans)
	oprot := protocolFactory.GetProtocol(trans)
	client := impalaservice.NewImpalaHiveServer2ServiceClient(thrift.NewTStandardClient(iprot, oprot))
	if err := trans.Open(); err != nil {
		fmt.Fprintln(os.Stderr, "Error opening socket to ", host, ":", port, " ", err)
		os.Exit(1)
	}
	
	switch cmd {
	case "ResetCatalog":
		if flag.NArg() - 1 != 0 {
			fmt.Fprintln(os.Stderr, "ResetCatalog requires 0 args")
			flag.Usage()
		}
		fmt.Print(client.ResetCatalog(context.Background()))
		fmt.Print("\n")
		break
	case "OpenSession":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "OpenSession requires 1 args")
			flag.Usage()
		}
		arg89 := flag.Arg(1)
		mbTrans90 := thrift.NewTMemoryBufferLen(len(arg89))
		defer mbTrans90.Close()
		_, err91 := mbTrans90.WriteString(arg89)
		if err91 != nil {
			Usage()
			return
		}
		factory92 := thrift.NewTJSONProtocolFactory()
		jsProt93 := factory92.GetProtocol(mbTrans90)
		argvalue0 := cli_service.NewTOpenSessionReq()
		err94 := argvalue0.Read(context.Background(), jsProt93)
		if err94 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.OpenSession(context.Background(), value0))
		fmt.Print("\n")
		break
	case "CloseSession":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "CloseSession requires 1 args")
			flag.Usage()
		}
		arg95 := flag.Arg(1)
		mbTrans96 := thrift.NewTMemoryBufferLen(len(arg95))
		defer mbTrans96.Close()
		_, err97 := mbTrans96.WriteString(arg95)
		if err97 != nil {
			Usage()
			return
		}
		factory98 := thrift.NewTJSONProtocolFactory()
		jsProt99 := factory98.GetProtocol(mbTrans96)
		argvalue0 := cli_service.NewTCloseSessionReq()
		err100 := argvalue0.Read(context.Background(), jsProt99)
		if err100 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.CloseSession(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetInfo":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetInfo requires 1 args")
			flag.Usage()
		}
		arg101 := flag.Arg(1)
		mbTrans102 := thrift.NewTMemoryBufferLen(len(arg101))
		defer mbTrans102.Close()
		_, err103 := mbTrans102.WriteString(arg101)
		if err103 != nil {
			Usage()
			return
		}
		factory104 := thrift.NewTJSONProtocolFactory()
		jsProt105 := factory104.GetProtocol(mbTrans102)
		argvalue0 := cli_service.NewTGetInfoReq()
		err106 := argvalue0.Read(context.Background(), jsProt105)
		if err106 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetInfo(context.Background(), value0))
		fmt.Print("\n")
		break
	case "ExecuteStatement":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "ExecuteStatement requires 1 args")
			flag.Usage()
		}
		arg107 := flag.Arg(1)
		mbTrans108 := thrift.NewTMemoryBufferLen(len(arg107))
		defer mbTrans108.Close()
		_, err109 := mbTrans108.WriteString(arg107)
		if err109 != nil {
			Usage()
			return
		}
		factory110 := thrift.NewTJSONProtocolFactory()
		jsProt111 := factory110.GetProtocol(mbTrans108)
		argvalue0 := cli_service.NewTExecuteStatementReq()
		err112 := argvalue0.Read(context.Background(), jsProt111)
		if err112 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.ExecuteStatement(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetTypeInfo":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetTypeInfo requires 1 args")
			flag.Usage()
		}
		arg113 := flag.Arg(1)
		mbTrans114 := thrift.NewTMemoryBufferLen(len(arg113))
		defer mbTrans114.Close()
		_, err115 := mbTrans114.WriteString(arg113)
		if err115 != nil {
			Usage()
			return
		}
		factory116 := thrift.NewTJSONProtocolFactory()
		jsProt117 := factory116.GetProtocol(mbTrans114)
		argvalue0 := cli_service.NewTGetTypeInfoReq()
		err118 := argvalue0.Read(context.Background(), jsProt117)
		if err118 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetTypeInfo(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetCatalogs":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetCatalogs requires 1 args")
			flag.Usage()
		}
		arg119 := flag.Arg(1)
		mbTrans120 := thrift.NewTMemoryBufferLen(len(arg119))
		defer mbTrans120.Close()
		_, err121 := mbTrans120.WriteString(arg119)
		if err121 != nil {
			Usage()
			return
		}
		factory122 := thrift.NewTJSONProtocolFactory()
		jsProt123 := factory122.GetProtocol(mbTrans120)
		argvalue0 := cli_service.NewTGetCatalogsReq()
		err124 := argvalue0.Read(context.Background(), jsProt123)
		if err124 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetCatalogs(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetSchemas":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetSchemas requires 1 args")
			flag.Usage()
		}
		arg125 := flag.Arg(1)
		mbTrans126 := thrift.NewTMemoryBufferLen(len(arg125))
		defer mbTrans126.Close()
		_, err127 := mbTrans126.WriteString(arg125)
		if err127 != nil {
			Usage()
			return
		}
		factory128 := thrift.NewTJSONProtocolFactory()
		jsProt129 := factory128.GetProtocol(mbTrans126)
		argvalue0 := cli_service.NewTGetSchemasReq()
		err130 := argvalue0.Read(context.Background(), jsProt129)
		if err130 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetSchemas(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetTables":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetTables requires 1 args")
			flag.Usage()
		}
		arg131 := flag.Arg(1)
		mbTrans132 := thrift.NewTMemoryBufferLen(len(arg131))
		defer mbTrans132.Close()
		_, err133 := mbTrans132.WriteString(arg131)
		if err133 != nil {
			Usage()
			return
		}
		factory134 := thrift.NewTJSONProtocolFactory()
		jsProt135 := factory134.GetProtocol(mbTrans132)
		argvalue0 := cli_service.NewTGetTablesReq()
		err136 := argvalue0.Read(context.Background(), jsProt135)
		if err136 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetTables(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetTableTypes":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetTableTypes requires 1 args")
			flag.Usage()
		}
		arg137 := flag.Arg(1)
		mbTrans138 := thrift.NewTMemoryBufferLen(len(arg137))
		defer mbTrans138.Close()
		_, err139 := mbTrans138.WriteString(arg137)
		if err139 != nil {
			Usage()
			return
		}
		factory140 := thrift.NewTJSONProtocolFactory()
		jsProt141 := factory140.GetProtocol(mbTrans138)
		argvalue0 := cli_service.NewTGetTableTypesReq()
		err142 := argvalue0.Read(context.Background(), jsProt141)
		if err142 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetTableTypes(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetColumns":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetColumns requires 1 args")
			flag.Usage()
		}
		arg143 := flag.Arg(1)
		mbTrans144 := thrift.NewTMemoryBufferLen(len(arg143))
		defer mbTrans144.Close()
		_, err145 := mbTrans144.WriteString(arg143)
		if err145 != nil {
			Usage()
			return
		}
		factory146 := thrift.NewTJSONProtocolFactory()
		jsProt147 := factory146.GetProtocol(mbTrans144)
		argvalue0 := cli_service.NewTGetColumnsReq()
		err148 := argvalue0.Read(context.Background(), jsProt147)
		if err148 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetColumns(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetFunctions":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetFunctions requires 1 args")
			flag.Usage()
		}
		arg149 := flag.Arg(1)
		mbTrans150 := thrift.NewTMemoryBufferLen(len(arg149))
		defer mbTrans150.Close()
		_, err151 := mbTrans150.WriteString(arg149)
		if err151 != nil {
			Usage()
			return
		}
		factory152 := thrift.NewTJSONProtocolFactory()
		jsProt153 := factory152.GetProtocol(mbTrans150)
		argvalue0 := cli_service.NewTGetFunctionsReq()
		err154 := argvalue0.Read(context.Background(), jsProt153)
		if err154 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetFunctions(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetOperationStatus":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetOperationStatus requires 1 args")
			flag.Usage()
		}
		arg155 := flag.Arg(1)
		mbTrans156 := thrift.NewTMemoryBufferLen(len(arg155))
		defer mbTrans156.Close()
		_, err157 := mbTrans156.WriteString(arg155)
		if err157 != nil {
			Usage()
			return
		}
		factory158 := thrift.NewTJSONProtocolFactory()
		jsProt159 := factory158.GetProtocol(mbTrans156)
		argvalue0 := cli_service.NewTGetOperationStatusReq()
		err160 := argvalue0.Read(context.Background(), jsProt159)
		if err160 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetOperationStatus(context.Background(), value0))
		fmt.Print("\n")
		break
	case "CancelOperation":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "CancelOperation requires 1 args")
			flag.Usage()
		}
		arg161 := flag.Arg(1)
		mbTrans162 := thrift.NewTMemoryBufferLen(len(arg161))
		defer mbTrans162.Close()
		_, err163 := mbTrans162.WriteString(arg161)
		if err163 != nil {
			Usage()
			return
		}
		factory164 := thrift.NewTJSONProtocolFactory()
		jsProt165 := factory164.GetProtocol(mbTrans162)
		argvalue0 := cli_service.NewTCancelOperationReq()
		err166 := argvalue0.Read(context.Background(), jsProt165)
		if err166 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.CancelOperation(context.Background(), value0))
		fmt.Print("\n")
		break
	case "CloseOperation":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "CloseOperation requires 1 args")
			flag.Usage()
		}
		arg167 := flag.Arg(1)
		mbTrans168 := thrift.NewTMemoryBufferLen(len(arg167))
		defer mbTrans168.Close()
		_, err169 := mbTrans168.WriteString(arg167)
		if err169 != nil {
			Usage()
			return
		}
		factory170 := thrift.NewTJSONProtocolFactory()
		jsProt171 := factory170.GetProtocol(mbTrans168)
		argvalue0 := cli_service.NewTCloseOperationReq()
		err172 := argvalue0.Read(context.Background(), jsProt171)
		if err172 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.CloseOperation(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetResultSetMetadata":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetResultSetMetadata requires 1 args")
			flag.Usage()
		}
		arg173 := flag.Arg(1)
		mbTrans174 := thrift.NewTMemoryBufferLen(len(arg173))
		defer mbTrans174.Close()
		_, err175 := mbTrans174.WriteString(arg173)
		if err175 != nil {
			Usage()
			return
		}
		factory176 := thrift.NewTJSONProtocolFactory()
		jsProt177 := factory176.GetProtocol(mbTrans174)
		argvalue0 := cli_service.NewTGetResultSetMetadataReq()
		err178 := argvalue0.Read(context.Background(), jsProt177)
		if err178 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetResultSetMetadata(context.Background(), value0))
		fmt.Print("\n")
		break
	case "FetchResults":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "FetchResults requires 1 args")
			flag.Usage()
		}
		arg179 := flag.Arg(1)
		mbTrans180 := thrift.NewTMemoryBufferLen(len(arg179))
		defer mbTrans180.Close()
		_, err181 := mbTrans180.WriteString(arg179)
		if err181 != nil {
			Usage()
			return
		}
		factory182 := thrift.NewTJSONProtocolFactory()
		jsProt183 := factory182.GetProtocol(mbTrans180)
		argvalue0 := cli_service.NewTFetchResultsReq()
		err184 := argvalue0.Read(context.Background(), jsProt183)
		if err184 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.FetchResults(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetDelegationToken":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetDelegationToken requires 1 args")
			flag.Usage()
		}
		arg185 := flag.Arg(1)
		mbTrans186 := thrift.NewTMemoryBufferLen(len(arg185))
		defer mbTrans186.Close()
		_, err187 := mbTrans186.WriteString(arg185)
		if err187 != nil {
			Usage()
			return
		}
		factory188 := thrift.NewTJSONProtocolFactory()
		jsProt189 := factory188.GetProtocol(mbTrans186)
		argvalue0 := cli_service.NewTGetDelegationTokenReq()
		err190 := argvalue0.Read(context.Background(), jsProt189)
		if err190 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetDelegationToken(context.Background(), value0))
		fmt.Print("\n")
		break
	case "CancelDelegationToken":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "CancelDelegationToken requires 1 args")
			flag.Usage()
		}
		arg191 := flag.Arg(1)
		mbTrans192 := thrift.NewTMemoryBufferLen(len(arg191))
		defer mbTrans192.Close()
		_, err193 := mbTrans192.WriteString(arg191)
		if err193 != nil {
			Usage()
			return
		}
		factory194 := thrift.NewTJSONProtocolFactory()
		jsProt195 := factory194.GetProtocol(mbTrans192)
		argvalue0 := cli_service.NewTCancelDelegationTokenReq()
		err196 := argvalue0.Read(context.Background(), jsProt195)
		if err196 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.CancelDelegationToken(context.Background(), value0))
		fmt.Print("\n")
		break
	case "RenewDelegationToken":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "RenewDelegationToken requires 1 args")
			flag.Usage()
		}
		arg197 := flag.Arg(1)
		mbTrans198 := thrift.NewTMemoryBufferLen(len(arg197))
		defer mbTrans198.Close()
		_, err199 := mbTrans198.WriteString(arg197)
		if err199 != nil {
			Usage()
			return
		}
		factory200 := thrift.NewTJSONProtocolFactory()
		jsProt201 := factory200.GetProtocol(mbTrans198)
		argvalue0 := cli_service.NewTRenewDelegationTokenReq()
		err202 := argvalue0.Read(context.Background(), jsProt201)
		if err202 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.RenewDelegationToken(context.Background(), value0))
		fmt.Print("\n")
		break
	case "GetLog":
		if flag.NArg() - 1 != 1 {
			fmt.Fprintln(os.Stderr, "GetLog requires 1 args")
			flag.Usage()
		}
		arg203 := flag.Arg(1)
		mbTrans204 := thrift.NewTMemoryBufferLen(len(arg203))
		defer mbTrans204.Close()
		_, err205 := mbTrans204.WriteString(arg203)
		if err205 != nil {
			Usage()
			return
		}
		factory206 := thrift.NewTJSONProtocolFactory()
		jsProt207 := factory206.GetProtocol(mbTrans204)
		argvalue0 := cli_service.NewTGetLogReq()
		err208 := argvalue0.Read(context.Background(), jsProt207)
		if err208 != nil {
			Usage()
			return
		}
		value0 := argvalue0
		fmt.Print(client.GetLog(context.Background(), value0))
		fmt.Print("\n")
		break
	case "":
		Usage()
	default:
		fmt.Fprintln(os.Stderr, "Invalid function ", cmd)
	}
}
