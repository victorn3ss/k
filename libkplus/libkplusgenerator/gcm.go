package libkplusgenerator

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	checkin_proto "kplus/pb/checkin"
	"kplus/shared"
	"net/http"
	"net/url"
	"strings"
)

func registerGCM() (*GcmCredentials, error) {
	checkInResp, err := checkInGcm(0, 0)
	if err != nil {
		return nil, err
	}

	return doRegisterGcm(*checkInResp.AndroidId, *checkInResp.SecurityToken)
}

func checkInGcm(androidID, securityToken uint64) (*checkin_proto.AndroidCheckinResponse, error) {
	requestProto := &checkin_proto.AndroidCheckinRequest{
		Checkin: &checkin_proto.AndroidCheckinProto{
			Type:       checkin_proto.DeviceType_DEVICE_ANDROID_OS.Enum(),
			UserNumber: proto.Int32(0),
		},
		Fragment:         proto.Int32(0),
		Version:          proto.Int32(3),
		UserSerialNumber: proto.Int32(0),
		Id:               proto.Int64(int64(androidID)),
		SecurityToken:    proto.Uint64(securityToken),
	}

	message, err := proto.Marshal(requestProto)
	if err != nil {
		return nil, errors.Wrap(err, "marshal GCM checkin request")
	}

	res, err := httpPost("https://android.clients.google.com/checkin", bytes.NewReader(message), func(header *http.Header) {
		header.Set("Content-Type", "application/x-protobuf")
	})
	if err != nil {
		return nil, errors.Wrap(err, "request GCM checkin")
	}
	defer res.Body.Close()

	// unauthorized error
	if res.StatusCode == http.StatusUnauthorized {
		return nil, errors.Errorf("server error: %d", res.StatusCode)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, errors.Errorf("server error: %s", res.Status)
	}
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read GCM checkin response")
	}

	responseProto := &checkin_proto.AndroidCheckinResponse{}
	err = proto.Unmarshal(data, responseProto)
	if err != nil {
		return nil, errors.Wrapf(err, "unmarshal GCM checkin response")
	}
	return responseProto, nil
}

type GcmCredentials struct {
	AndroidID     uint64
	SecurityToken uint64
	Token         string
}

func doRegisterGcm(androidID uint64, securityToken uint64) (*GcmCredentials, error) {
	values := url.Values{}
	values.Set("app", "com.kasikorn.retail.mbanking.wap")
	values.Set("device", fmt.Sprint(androidID))
	values.Set("sender", "305857576301")

	res, err := httpPost("https://android.clients.google.com/c2dm/register3", strings.NewReader(values.Encode()), func(header *http.Header) {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		header.Set("Authorization", fmt.Sprintf("AidLogin %d:%d", androidID, securityToken))
	})
	if err != nil {
		return nil, errors.Wrap(err, "request GCM register")
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read GCM register response")
	}

	queries, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, errors.Wrap(err, "parse GCM register URL")
	}

	if err := queries.Get("Error"); err != "" {
		return nil, errors.Errorf("response error: %s", err)
	}

	token := queries.Get("token")
	if token == "" {
		return nil, errors.New("missing token")
	}

	return &GcmCredentials{
		AndroidID:     androidID,
		SecurityToken: securityToken,
		Token:         token,
	}, nil
}

func httpPost(url string, body io.Reader, headerSetter func(*http.Header)) (*http.Response, error) {
	httpClient := shared.NewHttpClient()

	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, errors.Wrap(err, "create post request error")
	}
	headerSetter(&req.Header)

	return httpClient.Do(req)
}
