package reporedis

import (
	"fmt"
	"slices"
)

type IndexManager struct {
	space  string
	ln     int
	indexs map[string]string
}

func NewIndexManager(space string) *IndexManager {
	return &IndexManager{
		space:  space,
		indexs: make(map[string]string),
	}
}

func (im *IndexManager) SetIndex(field, val string) {
	im.indexs[field] = fmt.Sprintf("%s%s:%s", im.space, field, val)
	im.ln++
}

func (im *IndexManager) SetIndexesByFields(val string, fields ...string) {
	for _, field := range fields {
		im.indexs[field] = fmt.Sprintf("%s%s:%s", im.space, field, val)
		im.ln++
	}
}

func (im *IndexManager) DelIndex(field string) {
	_, ok := im.indexs[field]
	if ok {
		im.ln--
	}
	delete(im.indexs, field)
}

func (im *IndexManager) DelIndexByFields(fields ...string) {
	for _, field := range fields {
		_, ok := im.indexs[field]
		if ok {
			im.ln--
		}
		delete(im.indexs, field)
	}
}

func (im *IndexManager) DelByIndex(index string) {
	for key, val := range im.indexs {
		if val == index {
			im.ln--
			delete(im.indexs, key)
		}
	}
}

func (im *IndexManager) GetIndex(field string) (string, bool) {
	val, ok := im.indexs[field]
	return val, ok
}

func (im *IndexManager) GetIndexsByFields(fields ...string) ([]string, bool) {

	keys := make([]string, 0)
	var has bool

	for _, key := range fields {
		data, ok := im.indexs[key]
		if ok {
			keys = append(keys, data)
			has = true
		}
	}

	return keys, has
}

func (im *IndexManager) GetIndexs() ([]string, bool) {
	indexs := make([]string, 0)
	var ok bool

	for _, val := range im.indexs {
		indexs = append(indexs, val)
		ok = true
	}

	return indexs, ok
}

func (im *IndexManager) GetIndexsNotIncludedFields(fileds ...string) ([]string, bool) {

	indexs := make([]string, 0)
	var ok bool

	for key, val := range im.indexs {
		if !slices.Contains(fileds, key) {
			indexs = append(indexs, val)
			ok = true
		}
	}

	return indexs, ok
}

func (im *IndexManager) GetIndexsNotIncludedIndexs(indexs ...string) ([]string, bool) {

	newindexs := make([]string, 0)
	var ok bool

	for _, val := range im.indexs {
		if !slices.Contains(indexs, val) {
			newindexs = append(newindexs, val)
			ok = true
		}
	}

	return newindexs, ok
}

func (im *IndexManager) GetFieldsNotIncludedIndexs(indexs ...string) ([]string, bool) {

	fields := make([]string, 0)
	var ok bool

	for key, val := range im.indexs {
		if !slices.Contains(indexs, val) {
			fields = append(fields, key)
			ok = true
		}
	}

	return fields, ok
}

func (im *IndexManager) GetFieldByIndex(index string) (string, bool) {

	var field string
	var ok bool

	for key, val := range im.indexs {
		if index == val {
			field = key
			ok = true
			break
		}
	}

	return field, ok
}

func (im *IndexManager) GetFields() ([]string, bool) {

	fields := make([]string, 0)
	var ok bool

	for key := range im.indexs {
		fields = append(fields, key)
		ok = true
	}

	return fields, ok
}

func (im *IndexManager) GetFieldsByIndexs(indexs ...string) ([]string, bool) {

	fields := make([]string, 0)
	var ok bool

	for key, val := range im.indexs {
		if slices.Contains(indexs, val) {
			fields = append(fields, key)
			ok = true
		}
	}

	return fields, ok
}

func (im *IndexManager) Len() int {
	return im.ln
}
