package shared

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

var (
	baseUrlHttps = "https://rt10.kasikornbank.com/kplus-service"
	baseUrlHttp  = "http://rt10.kasikornbank.com/kplus-service"
)

type kplusClient struct {
	httpClient *http.Client
	isEncrypt  bool
	sessionId  string
	hashV      string
	privateKey *ecdsa.PrivateKey
	key        []byte
	iv         []byte
}

type RequestHeader struct {
	SessionId string `json:"sessionId"`
	HashV     string `json:"hashV"`
	Command   string `json:"command"`
}

type requestBody struct {
	ClientData interface{} `json:"clientData"`
}

type request struct {
	RequestHeader RequestHeader `json:"requestHeader"`
	RequestBody   requestBody   `json:"requestBody"`
}

type ResponseHeader struct {
	Status      string  `json:"status"`
	MessageCode *string `json:"messageCode"`
	MessageDesc *string `json:"messageDesc"`
	DisplayText *string `json:"displayText"`
}
type response struct {
	ResponseHeader ResponseHeader `json:"responseHeader"`
	ResponseBody   interface{}    `json:"responseBody"`
}
type exchangeRequestData struct {
	AppName                   string `json:"appName"`
	AppVersion                string `json:"appVersion"`
	ConfigModifyDateTime      string `json:"configModifyDateTime"`
	DynamicMenuModifyDateTime string `json:"dynamicMenuModifyDateTime"`
	ForceUpdatedDate          string `json:"forceUpdatedDate"`
	LabelModifyDateTime       string `json:"labelModifyDateTime"`
	Language                  string `json:"language"`
	MenuModifyDateTime        string `json:"menuModifyDateTime"`
	MessageModifyDateTime     string `json:"messageModifyDateTime"`
	OsVersion                 string `json:"osVersion"`
	Platform                  string `json:"platform"`
	PublicKeyA                string `json:"publicKeyA"`
}

type exchangeResponseData struct {
	T1               string `json:"t1"`
	EncryptFlag      string `json:"encryptFlag"`
	PublicKeyW       string `json:"publicKeyW"`
	ServerDateTime   int    `json:"serverDateTime"`
	PublicKeyC       string `json:"publicKeyC"`
	SeasonalSlipData struct {
		SeasonalSlipURL            string `json:"seasonalSlipUrl"`
		SeasonalSlipModifyDateTime string `json:"seasonalSlipModifyDateTime"`
	} `json:"seasonalSlipData"`
	HashV string `json:"hashV"`
}

type receiveMobileNoRequestData struct {
	NetworkType string `json:"networkType"`
	T1          string `json:"t1"`
}

func (c *kplusClient) Init(networkType string) error {
	privateKey, err := GenerateKey()
	if err != nil {
		return err
	}
	c.privateKey = privateKey
	c.sessionId = GenerateSessionId()

	exchangeRequest := exchangeRequestData{
		AppName:                   "KPLUS_Victoria",
		AppVersion:                "5.15.3",
		ConfigModifyDateTime:      "20220125232851490",
		DynamicMenuModifyDateTime: "20210522231551703",
		ForceUpdatedDate:          "20180420160313",
		LabelModifyDateTime:       "20220125193750360",
		Language:                  "T",
		MenuModifyDateTime:        "20220125193750360",
		MessageModifyDateTime:     "20220118182153423",
		OsVersion:                 "11",
		Platform:                  "android",
		PublicKeyA:                MarshalPublicKey(&c.privateKey.PublicKey),
	}

	exchangeResponse := exchangeResponseData{}
	err = c.call(baseUrlHttps+"/security/exchangeKeyAndConfigV2", c.sessionId, "", "SECURITY", exchangeRequest, &exchangeResponse)
	if err != nil {
		return err
	}

	publicKey, err := ParsePublicKey(exchangeResponse.PublicKeyC)
	if err != nil {
		return err
	}

	sharedKey, _ := c.privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, c.privateKey.D.Bytes())

	c.key = sharedKey.Bytes()
	c.iv = []byte(c.sessionId[6:22])
	c.isEncrypt = true

	err = c.call(baseUrlHttp+"/security/receiveMobileNo", c.sessionId, exchangeResponse.HashV, "SECURITY", receiveMobileNoRequestData{
		NetworkType: networkType,
		T1:          exchangeResponse.T1,
	}, struct{}{})
	if err != nil {
		return err
	}

	return nil
}

func (c *kplusClient) SecurityCreateAuthenID(da3, dm1 string) (string, error) {
	resp := struct {
		Dka3 string `json:"dka3"`
	}{}
	err := c.call(baseUrlHttps+"/security/createAuthenID", c.sessionId, c.hashV, "SECURITY", struct {
		Da3 string `json:"da3"`
		Dm1 string `json:"dm1"`
	}{
		Da3: da3,
		Dm1: dm1,
	}, &resp)
	if err != nil {
		return "", err
	}

	return resp.Dka3, nil
}

type checkAuthenIDAndProfileResponseData struct {
	NormalLoginFlag            string `json:"normalLoginFlag"`
	DebugFlag                  string `json:"debugFlag"`
	TouchOnFlag                string `json:"touchOnFlag"`
	VerifyCitizenFlag          string `json:"verifyCitizenFlag"`
	DevSettingFlag             string `json:"devSettingFlag"`
	ChangeUsernameFlag         string `json:"changeUsernameFlag"`
	UserPermission             string `json:"userPermission"`
	VerifyEmailFlag            string `json:"verifyEmailFlag"`
	InboxSessionID             string `json:"inboxSessionId"`
	ForceUpdatePresettingFlag  string `json:"forceUpdatePresettingFlag"`
	GotoPage                   string `json:"gotoPage"`
	Username                   string `json:"username"`
	UnlockOnlineStatus         string `json:"unlockOnlineStatus"`
	AgreeTermFlag              string `json:"agreeTermFlag"`
	VerifyEmailFlagSetting     string `json:"verifyEmailFlagSetting"`
	WebInboxSessionID          string `json:"webInboxSessionId"`
	LoginFirstTimeAfterUpgrade string `json:"loginFirstTimeAfterUpgrade"`
	LoginProfileFullFirstTime  string `json:"loginProfileFullFirstTime"`
	GotoPageMessageEN          string `json:"gotoPageMessageEN"`
	ForceChangePinFlag         string `json:"forceChangePinFlag"`
	MenuModifyDateTime         string `json:"menuModifyDateTime"`
	PartnerTokenID             string `json:"partnerTokenId"`
	NewMobileNo                string `json:"newMobileNo"`
	WatchOnFlag                string `json:"watchOnFlag"`
	GotoPageMessageTH          string `json:"gotoPageMessageTH"`
	SessionID                  string `json:"sessionId"`
	BeaconFlag                 string `json:"beaconFlag"`
	Language                   string `json:"language"`
	UUID                       string `json:"uuid"`
	MobileNo                   string `json:"mobileNo"`
}

func (c *kplusClient) SecurityCheckAuthenIDAndProfile(dka3, dm1 string) (*checkAuthenIDAndProfileResponseData, error) {
	resp := &checkAuthenIDAndProfileResponseData{}
	req := struct {
		ModelName          string `json:"modelName"`
		Db1                string `json:"db1"`
		Dka3               string `json:"dka3"`
		Dm1                string `json:"dm1"`
		WifiKey            string `json:"wifiKey"`
		ModelType          string `json:"modelType"`
		Token              string `json:"token"`
		MenuModifyDateTime string `json:"menuModifyDateTime"`
		DetectDetail       string `json:"detectDetail"`
	}{
		ModelName:          "M2007J20CT",
		Db1:                "",
		Dka3:               dka3,
		Dm1:                dm1,
		WifiKey:            "",
		ModelType:          "2",
		Token:              "e0yhlD_nRfuodyaSQvEMBF:APA91bERHTLhgjF4tf9i_awgjIXsGGjDjd1th67mGcowVvPBsoI-vQ3c_wXzwKDvCfRonRd4wDPQYYwpKlYbEtPAo71CEhRe0086bASm218cK_S-HdOF8Lw347zakP9rZI-EYroej2LY",
		MenuModifyDateTime: "20220125193750360",
		DetectDetail:       "",
	}

	err := c.call(baseUrlHttps+"/security/checkAuthenIDAndProfile", c.sessionId, c.hashV, "SECURITY", req, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type MobileUtilityUnlockOnlineRequestData struct {
	AccountNumber string `json:"accountNumber"`
	DocumentID    string `json:"documentId"`
	Pin           string `json:"pin"`
	Dm1           string `json:"dm1"`
	Dka3          string `json:"dka3"`
}

type mobileUtilityUnlockOnlineResponseData struct {
	FreeText string `json:"freeText"`
	Db1      string `json:"db1"`
}

func (c *kplusClient) MobileUtilityUnlockOnline(sessionID string, req MobileUtilityUnlockOnlineRequestData) (*mobileUtilityUnlockOnlineResponseData, error) {
	resp := &mobileUtilityUnlockOnlineResponseData{}

	err := c.call(baseUrlHttps+"/mobileUtility/unlockOnline", sessionID, "", "SECURITY", req, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type SecurityVerifyPinRequestData struct {
	Pin                   string `json:"pin"`
	Dm1                   string `json:"dm1"`
	Dka3                  string `json:"dka3"`
	ChannelDetail         string `json:"channelDetail"`
	Latitude              string `json:"latitude"`
	Longitude             string `json:"longitude"`
	ListAccountFlag       string `json:"listAccountFlag"`
	NeedUpdateSessionFlag string `json:"needUpdateSessionFlag"`
}

type SecurityVerifyPinResponseData struct {
	TotalOfRecord   int    `json:"totalOfRecord"`
	EndOfRecordFlag string `json:"endOfRecordFlag"`
	AccountList     []struct {
		MenuItemNumber        int         `json:"menuItemNumber"`
		AccountNumber         string      `json:"accountNumber"`
		AccountType           string      `json:"accountType"`
		AccountAliasName      string      `json:"accountAliasName"`
		AccountStatus         string      `json:"accountStatus"`
		DefaultAccountFlag    string      `json:"defaultAccountFlag"`
		MaskAccountFlag       string      `json:"maskAccountFlag"`
		ShowBalanceFlag       string      `json:"showBalanceFlag"`
		CardType              interface{} `json:"cardType"`
		CardHolderFlag        interface{} `json:"cardHolderFlag"`
		KecCardFlag           interface{} `json:"kecCardFlag"`
		MainCustomerFlag      interface{} `json:"mainCustomerFlag"`
		ESavingFlag           string      `json:"eSavingFlag"`
		ESavingStatus         interface{} `json:"eSavingStatus"`
		AccumulatedAmount     float64     `json:"accumulatedAmount"`
		LimitAmount           float64     `json:"limitAmount"`
		ShowSmartPayMenuFlag  string      `json:"showSmartPayMenuFlag"`
		ShowSmartCashMenuFlag string      `json:"showSmartCashMenuFlag"`
		ShowCardInfoFlag      string      `json:"showCardInfoFlag"`
		ShowWithdrawMenuFlag  string      `json:"showWithdrawMenuFlag"`
		CardImgURL            string      `json:"cardImgUrl"`
	} `json:"accountList"`
	AvailableFinancialLimit string `json:"availableFinancialLimit"`
	ForceChangePINFlag      string `json:"forceChangePINFlag"`
	FreeText                string `json:"freeText"`
	EmailAddress            string `json:"emailAddress"`
	MenuFlag                string `json:"menuFlag"`
	WebInboxSessionID       string `json:"webInboxSessionId"`
	SessionID               string `json:"sessionId"`
	ConsolidatedPortFlag    string `json:"consolidatedPortFlag"`
	KMerchantAccount        string `json:"kMerchantAccount"`
	RegisteredAccount       string `json:"registeredAccount"`
	Db1                     string `json:"db1"`
	TotalFinancialLimit     string `json:"totalFinancialLimit"`
	AllowFTFlag             string `json:"allowFTFlag"`
	NumberOfAccounts        int    `json:"numberOfAccounts"`
	MenuFlagLength          int    `json:"menuFlagLength"`
}

//command ONBOARD_PRESETTING
func (c *kplusClient) SecurityVerifyPin(sessionID string, req SecurityVerifyPinRequestData, command string) (*SecurityVerifyPinResponseData, error) {
	resp := &SecurityVerifyPinResponseData{}
	if command == "" {
		command = "SECURITY"
	}
	err := c.call(baseUrlHttps+"/security/verifyPin", sessionID, "", command, req, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type MobileUtilityListOwnAccountRequestData struct {
	ListType              string `json:"listType"`
	Exclude               string `json:"exclude"`
	StartRecord           string `json:"startRecord"`
	NumberOfRecord        string `json:"numberOfRecord"`
	IsTouchIDLogin        string `json:"isTouchIDLogin"`
	IsUnlockOnlineProcess string `json:"isUnlockOnlineProcess"`
	ChannelDetail         string `json:"channelDetail"`
	Latitude              string `json:"latitude"`
	Longitude             string `json:"longitude"`
}

type mobileUtilityListOwnAccountResponseData struct {
	MenuFlag             string `json:"menuFlag"`
	MenuFlagLength       int    `json:"menuFlagLength"`
	EmailAddress         string `json:"emailAddress"`
	NumberOfAccounts     int    `json:"numberOfAccounts"`
	TotalOfRecord        int    `json:"totalOfRecord"`
	EndOfRecordFlag      string `json:"endOfRecordFlag"`
	ConsolidatedPortFlag string `json:"consolidatedPortFlag"`
	AllowFTFlag          string `json:"allowFTFlag"`
	RegisteredAccount    string `json:"registeredAccount"`
	ProfileStatus        string `json:"profileStatus"`
	ForceChangePINFlag   string `json:"forceChangePINFlag"`
	KMerchantAccount     string `json:"kMerchantAccount"`
	AccountList          []struct {
		MenuItemNumber        int         `json:"menuItemNumber"`
		AccountNumber         string      `json:"accountNumber"`
		AccountType           string      `json:"accountType"`
		AccountAliasName      string      `json:"accountAliasName"`
		AccountStatus         string      `json:"accountStatus"`
		DefaultAccountFlag    string      `json:"defaultAccountFlag"`
		MaskAccountFlag       string      `json:"maskAccountFlag"`
		ShowBalanceFlag       string      `json:"showBalanceFlag"`
		CardType              interface{} `json:"cardType"`
		CardHolderFlag        interface{} `json:"cardHolderFlag"`
		KecCardFlag           interface{} `json:"kecCardFlag"`
		MainCustomerFlag      interface{} `json:"mainCustomerFlag"`
		ESavingFlag           string      `json:"eSavingFlag"`
		ESavingStatus         interface{} `json:"eSavingStatus"`
		AccumulatedAmount     float64     `json:"accumulatedAmount"`
		LimitAmount           float64     `json:"limitAmount"`
		ShowSmartPayMenuFlag  string      `json:"showSmartPayMenuFlag"`
		ShowSmartCashMenuFlag string      `json:"showSmartCashMenuFlag"`
		ShowCardInfoFlag      string      `json:"showCardInfoFlag"`
		ShowWithdrawMenuFlag  string      `json:"showWithdrawMenuFlag"`
		CardImgURL            string      `json:"cardImgUrl"`
	} `json:"accountList"`
	TotalFinancialLimit     string `json:"totalFinancialLimit"`
	AvailableFinancialLimit string `json:"availableFinancialLimit"`
	FreeText                string `json:"freeText"`
}

func (c *kplusClient) MobileUtilityListOwnAccount(sessionId string, req MobileUtilityListOwnAccountRequestData) (*mobileUtilityListOwnAccountResponseData, error) {
	resp := &mobileUtilityListOwnAccountResponseData{}

	err := c.call(baseUrlHttps+"/mobileUtility/listOwnAccount", sessionId, c.hashV, "SECURITY", req, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type SettingPreSettingV2Consent struct {
	ConsentFlag string `json:"consentFlag"`
	ConsentType string `json:"consentType"`
}

type SettingPreSettingV2RequestData struct {
	AccountNumber   string                       `json:"accountNumber"`
	AllowFTFlag     string                       `json:"allowFTFlag"`
	MaskAccountFlag string                       `json:"maskAccountFlag"`
	ShowBalanceFlag string                       `json:"showBalanceFlag"`
	TouchStatus     string                       `json:"touchStatus"`
	WifiStatus      string                       `json:"wifiStatus"`
	ConsentList     []SettingPreSettingV2Consent `json:"consentList"`
}

type settingPreSettingV2ResponseData struct {
	TouchStatus   string `json:"touchStatus"`
	WifiStatus    string `json:"wifiStatus"`
	WifiAuthenKey string `json:"wifiAuthenKey"`
	FreeText      string `json:"freeText"`
}

func (c *kplusClient) SettingPreSettingV2(sessionId string, req SettingPreSettingV2RequestData) (*settingPreSettingV2ResponseData, error) {
	resp := &settingPreSettingV2ResponseData{}

	err := c.call(baseUrlHttps+"/setting/preSettingV2", sessionId, "", "ONBOARD_PRESETTING", req, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (c *kplusClient) call(url, sessionId, hashV, command string, data interface{}, responseBody interface{}) error {
	var clientData interface{}

	if c.isEncrypt {
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			return err
		}

		encrypt, err := c.encrypt(string(jsonBytes))
		if err != nil {
			return err
		}

		clientData = encrypt
	} else {
		clientData = data
	}

	bodyBytes, err := json.Marshal(request{
		RequestHeader: RequestHeader{
			SessionId: sessionId,
			HashV:     hashV,
			Command:   command,
		},
		RequestBody: requestBody{
			ClientData: clientData,
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "okhttp/4.9.1")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	v := &response{}
	err = json.Unmarshal(body, v)
	if err != nil && c.isEncrypt {
		decrypted, err := c.decrypt(string(body))
		if err != nil {
			return err
		}

		body = []byte(decrypted)
	}

	v = &response{ResponseBody: &responseBody}
	err = json.Unmarshal(body, v)
	if err != nil {
		return err
	}
	if v.ResponseHeader.MessageDesc != nil {
		var text string
		if v.ResponseHeader.DisplayText != nil {
			text = fmt.Sprintf("%s, %s", *v.ResponseHeader.MessageDesc, *v.ResponseHeader.DisplayText)
		} else {
			text = *v.ResponseHeader.MessageDesc
		}
		return errors.New(text)
	}

	return err
}

func (c *kplusClient) encrypt(data string) (string, error) {
	dst, err := AesCBCEncrypt([]byte(data), c.key, c.iv)
	if err != nil {
		return "", err
	}

	return Base64Encode(dst), nil
}

func (c *kplusClient) decrypt(src string) (string, error) {
	b, err := Base64Decode(src)
	if err != nil {
		return "", err
	}

	dst, err := AesCBCDecrypt(b, c.key, c.iv)
	if err != nil {
		return "", err
	}

	return string(dst), nil
}

func NewClient() (*kplusClient, error) {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &kplusClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext:     dialContext,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Jar: jar,
		},
		isEncrypt: false,
	}, nil
}
