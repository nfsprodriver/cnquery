package core

import (
	"errors"

	"go.mondoo.io/mondoo/motor/providers"
	ipmi_transport "go.mondoo.io/mondoo/motor/providers/ipmi"
	"go.mondoo.io/mondoo/resources/packs/core/ipmi"
)

func getIpmiInstance(t providers.Transport) (*ipmi.IpmiClient, error) {
	it, ok := t.(*ipmi_transport.Provider)
	if !ok {
		return nil, errors.New("ipmi resource is not supported on this transport")
	}

	return it.Client(), nil
}

func (a *mqlIpmi) id() (string, error) {
	return "ipmi", nil
}

func (a *mqlIpmi) GetGuid() (string, error) {
	client, err := getIpmiInstance(a.MotorRuntime.Motor.Provider)
	if err != nil {
		return "", err
	}

	resp, err := client.DeviceGUID()
	if err != nil {
		return "", err
	}
	return resp.GUID, nil
}

func (a *mqlIpmi) GetDeviceID() (map[string]interface{}, error) {
	client, err := getIpmiInstance(a.MotorRuntime.Motor.Provider)
	if err != nil {
		return nil, err
	}

	resp, err := client.DeviceID()
	if err != nil {
		return nil, err
	}

	return JsonToDict(resp)
}

func (a *mqlIpmiChassis) id() (string, error) {
	return "ipmi.chassis", nil
}

func (a *mqlIpmiChassis) GetStatus() (map[string]interface{}, error) {
	client, err := getIpmiInstance(a.MotorRuntime.Motor.Provider)
	if err != nil {
		return nil, err
	}

	resp, err := client.ChassisStatus()
	if err != nil {
		return nil, err
	}

	return JsonToDict(resp)
}

func (a *mqlIpmiChassis) GetSystemBootOptions() (map[string]interface{}, error) {
	client, err := getIpmiInstance(a.MotorRuntime.Motor.Provider)
	if err != nil {
		return nil, err
	}

	resp, err := client.ChassisSystemBootOptions()
	if err != nil {
		return nil, err
	}

	return JsonToDict(resp)
}