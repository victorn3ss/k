package libkplusgenerator

import "C"
import (
	"encoding/json"
	"kplus/shared"
	"time"
)

// Generator :
type Generator struct {
}

type generateState struct {
	Da3                   string `json:"da3"`
	Dm1                   string `json:"dm1"`
	Dka3                  string `json:"dka3"`
	Db1                   string `json:"db1"`
	WifiKey               string `json:"wifiKey"`
	AndroidID             uint64 `json:"androidId"`
	SecurityToken         uint64 `json:"securityToken"`
	Token                 string `json:"token"`
}

// Register : Register
func (p *Generator) Register(accountNumber, documentId, pin string) (string, error) {
	state := generateState{}

	if err := registerStep1(&state, accountNumber, documentId, pin); err != nil {
		return "", err
	}

	verifyPinResponseData, err := registerStep2(&state, accountNumber, pin)
	if err != nil {
		return "", err
	}

	marshal, err := json.Marshal(struct {
		State generateState                        `json:"state"`
		Extra shared.SecurityVerifyPinResponseData `json:"extra"`
	}{
		State: state,
		Extra: *verifyPinResponseData,
	})
	if err != nil {
		return "", err
	}

	return string(marshal), nil
}

func registerStep1(state *generateState, accountNumber, documentId, pin string) error {
	credentials, err := registerGCM()
	if err != nil {
		return err
	}

	state.AndroidID = credentials.AndroidID
	state.SecurityToken = credentials.SecurityToken
	state.Token = credentials.Token

	state.Da3 = randomAuthenId3()
	state.Dm1 = randomMac()

	client, err := shared.NewClient()
	if err != nil {
		return err
	}

	if err := client.Init("1"); err != nil {
		return err
	}

	dka3, err := client.SecurityCreateAuthenID(state.Da3, state.Dm1)
	if err != nil {
		return err
	}
	state.Dka3 = dka3

	profile, err := client.SecurityCheckAuthenIDAndProfile(state.Dka3, state.Dm1)
	if err != nil {
		return err
	}

	time.Sleep(1)

	online, err := client.MobileUtilityUnlockOnline(profile.SessionID, shared.MobileUtilityUnlockOnlineRequestData{
		AccountNumber: accountNumber,
		DocumentID:    documentId,
		Pin:           pin,
		Dm1:           state.Dm1,
		Dka3:          state.Dka3,
	})
	if err != nil {
		return err
	}

	state.Db1 = online.Db1

	return nil
}

func registerStep2(state *generateState, accountNumber, pin string) (*shared.SecurityVerifyPinResponseData, error) {
	client, err := shared.NewClient()
	if err != nil {
		return nil, err
	}
	if err := client.Init("1"); err != nil {
		return nil, err
	}

	profile, err := client.SecurityCheckAuthenIDAndProfile(state.Dka3, state.Dm1)
	if err != nil {
		return nil, err
	}

	_, err = client.MobileUtilityListOwnAccount(profile.SessionID, shared.MobileUtilityListOwnAccountRequestData{
		ListType:              "ALL",
		StartRecord:           "1",
		NumberOfRecord:        "-1",
		IsTouchIDLogin:        "Y",
		IsUnlockOnlineProcess: "Y",
		Latitude:              "0",
		Longitude:             "0",
	})
	if err != nil {
		return nil, err
	}

	verifyPin, err := client.SecurityVerifyPin(profile.SessionID, shared.SecurityVerifyPinRequestData{
		Pin:                   pin,
		Dm1:                   state.Dm1,
		Dka3:                  state.Dka3,
		Latitude:              "0",
		Longitude:             "0",
		ListAccountFlag:       "Y",
		NeedUpdateSessionFlag: "Y",
	}, "ONBOARD_PRESETTING")
	if err != nil {
		return nil, err
	}

	state.Db1 = verifyPin.Db1

	preSettingV2, err := client.SettingPreSettingV2(verifyPin.SessionID, shared.SettingPreSettingV2RequestData{
		AccountNumber:   accountNumber,
		AllowFTFlag:     "Y",
		MaskAccountFlag: "Y",
		ShowBalanceFlag: "Y",
		TouchStatus:     "Y",
		WifiStatus:      "Y",
		ConsentList: []shared.SettingPreSettingV2Consent{
			{
				ConsentFlag: "Y",
				ConsentType: "M",
			},
		},
	})
	if err != nil {
		return nil, err
	}

	state.WifiKey = preSettingV2.WifiAuthenKey

	return verifyPin, nil
}
