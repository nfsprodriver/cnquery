package convert

import "encoding/json"

// TODO: These functions are very heavyweight and prime candidates to
// be replaced by better laternatives.

// JsonToDict converts a raw golang object (typically loaded from JSON)
// into a `dict` type
func JsonToDict(v interface{}) (map[string]interface{}, error) {
	res := make(map[string]interface{})

	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(data), &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// JsonToDict converts a raw golang object (typically loaded from JSON)
// into an array of `dict` types
func JsonToDictSlice(v interface{}) ([]interface{}, error) {
	res := []interface{}{}

	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(data), &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
