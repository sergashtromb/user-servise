package index

import (
	"fmt"
	"slices"
	"user_service/infrastructure/reporedis/patch"
)

type IndexDiff struct {
	ToAdd    *IndexManager
	ToDelete *IndexManager
	ToExpire *IndexManager
}

type IndexManager struct {
	space     string
	indexable map[string]struct{}
	indexs    map[string]string
}

func NewIndexManager(space string, fields ...string) *IndexManager {

	im := IndexManager{
		space:     space,
		indexable: make(map[string]struct{}),
		indexs:    make(map[string]string),
	}

	for _, field := range fields {
		im.indexable[field] = struct{}{}
	}

	return &im
}

func (im *IndexManager) ApplyPatch(patchs []patch.FieldPatch) *IndexManager {

	res := im.clone()

	for _, fieldPatch := range patchs {

		if _, ok := res.indexable[fieldPatch.Name]; !ok {
			continue
		}

		switch fieldPatch.Action {
		case patch.FPSetField:
			res.SetIndex(fieldPatch.Name, fieldPatch.Value)
		case patch.FPClearField:
			delete(res.indexs, fieldPatch.Name)
		}
	}

	return res
}

func (im *IndexManager) Diff(old *IndexManager) *IndexDiff {

	id := IndexDiff{
		ToAdd:    NewIndexManager(im.space),
		ToDelete: NewIndexManager(im.space),
		ToExpire: NewIndexManager(im.space),
	}

	for key, val := range im.indexs {

		data, ok := old.GetIndex(key)
		if !ok {
			// old hasnt field -> toAdd
			id.ToAdd.indexs[key] = val
		} else if val == data {
			// old and new have common index -> toExpire
			id.ToExpire.indexs[key] = val
		} else {
			// old and new have field, but indexs dotn equal -> new toAdd old toDeleted
			id.ToAdd.indexs[key] = val
			id.ToDelete.indexs[key] = data
		}
	}

	// that been in old and new havnt that
	for key, val := range old.indexs {
		if _, ok := im.indexs[key]; !ok {
			id.ToDelete.indexs[key] = val
		}
	}

	return &id
}

func (im *IndexManager) SetIndex(field, val string) {
	if _, ok := im.indexable[field]; ok {
		im.indexs[field] = fmt.Sprintf("%s%s:%s", im.space, field, val)
	}
}

func (im *IndexManager) SetIndexesByFields(val string, fields ...string) {
	for _, field := range fields {
		if _, ok := im.indexable[field]; ok {
			im.indexs[field] = fmt.Sprintf("%s%s:%s", im.space, field, val)
		}
	}
}

func (im *IndexManager) DelIndex(field string) {
	delete(im.indexs, field)
}

func (im *IndexManager) DelIndexByFields(fields ...string) {
	for _, field := range fields {
		delete(im.indexs, field)
	}
}

func (im *IndexManager) DelByIndex(index string) {
	for key, val := range im.indexs {
		if val == index {
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
	return len(im.indexs)
}

func (im *IndexManager) clone() *IndexManager {
	c := NewIndexManager(im.space)
	c.indexable = im.indexable
	for k, v := range im.indexs {
		c.indexs[k] = v
	}
	return c
}
