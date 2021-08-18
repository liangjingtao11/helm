/*
Copyright (c) 2017 Easystack, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package loader

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/release"
)

var delsum = sha256.Sum224([]byte("9011bff6ddd27e9a656e3163d2a8d3f2"))
var sum = sha256.Sum224([]byte("08ff80583883217bb07ed23728aa8511"))
var key = sum[:24]

var magicGzip = []byte{0x1f, 0x8b, 0x08}

func CheckKey(k string) bool {
	h := md5.New()
	io.WriteString(h, k)
	return sha256.Sum224([]byte(hex.EncodeToString(h.Sum(nil)))) == sum
}

func CheckDeleteKey(k string) bool {
	h := md5.New()
	io.WriteString(h, k)
	return sha256.Sum224([]byte(hex.EncodeToString(h.Sum(nil)))) == delsum
}

// Encrypt
func TripleDesEncrypt(origData []byte) (_ []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	defer func() {
		if recover() != nil {
			err = errors.New("Authorization failed.")
		}
	}()

	origData, err = encodeRelease(origData)
	if err != nil {
		return nil, err
	}

	origData = PKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	cryptedData := make([]byte, len(origData))
	blockMode.CryptBlocks(cryptedData, origData)
	return cryptedData, nil
}

// Decrypt
func TripleDesDecrypt(cryptedData []byte) (_ []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	defer func() {
		if recover() != nil {
			err = errors.New("Prohibit the installation of unauthorized software packages.")
		}
	}()
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	origData := make([]byte, len(cryptedData))
	blockMode.CryptBlocks(origData, cryptedData)
	origData = PKCS5UnPadding(origData)

	origData, err = decodeRelease(origData)
	if err != nil {
		return nil, err
	}

	return origData, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// Chart Values Encrypt
func ChartValuesEncrypt(values string) (string, error) {
	valuesData := []byte(values)
	valuesData, err := TripleDesEncrypt(valuesData)
	if err != nil {
		return values, err
	}
	return string(valuesData), nil
}

// Chart Values Decrypt
func ChartValuesDecrypt(values string) (string, error) {
	valuesData := []byte(values)
	valuesData, err := TripleDesDecrypt(valuesData)
	if err != nil {
		return values, err
	}
	return string(valuesData), nil
}

// Chart Templates Encrypt
func ChartTemplatesEncrypt(templates []*chart.File) ([]*chart.File, error) {
	for _, v := range templates {
		var err error
		v.Data, err = TripleDesEncrypt(v.Data)
		if err != nil {
			return templates, err
		}
	}
	return templates, nil
}

// Chart Templates Decrypt
func ChartTemplatesDecrypt(templates []*chart.File) ([]*chart.File, error) {
	for _, v := range templates {
		var err error
		v.Data, err = TripleDesDecrypt(v.Data)
		if err != nil {
			return templates, err
		}
	}
	return templates, nil
}

// Hooks Encrypt
func HooksEncrypt(hooks []*release.Hook) ([]*release.Hook, error) {
	for _, h := range hooks {
		valuesData := []byte(h.Manifest)
		valuesData, err := TripleDesEncrypt(valuesData)
		if err != nil {
			return hooks, err
		}
		h.Manifest = string(valuesData)
	}
	return hooks, nil
}

// Hooks Decrypt
func HooksDecrypt(hooks []*release.Hook) ([]*release.Hook, error) {
	for _, h := range hooks {
		valuesData := []byte(h.Manifest)
		valuesData, err := TripleDesDecrypt(valuesData)
		if err != nil {
			return hooks, err
		}
		h.Manifest = string(valuesData)
	}
	return hooks, nil
}

// Chart Encrypt
func ChartEncrypt(chart *chart.Chart) (*chart.Chart, error) {
	var err error
	//todo: old chart.Raw is String, new chart.Raw is Chart.File
	// chart.Raw, err = ChartValuesEncrypt(chart.Raw)
	if err != nil {
		return nil, err
	}
	chart.Templates, err = ChartTemplatesEncrypt(chart.Templates)
	if err != nil {
		return nil, err
	}
	return chart, nil
}

// Chart Decrypt
func ChartDecrypt(chart *chart.Chart) (*chart.Chart, error) {
	var err error
	// chart.Raw, err = ChartValuesDecrypt(chart.Raw)
	if err != nil {
		return nil, err
	}
	chart.Templates, err = ChartTemplatesDecrypt(chart.Templates)
	if err != nil {
		return nil, err
	}
	return chart, nil
}

// Release Encrypt
func ReleaseEncrypt(release *release.Release) (*release.Release, error) {
	var err error
	release.Chart, err = ChartEncrypt(release.Chart)
	if err != nil {
		return nil, err
	}
	release.Manifest, err = ChartValuesEncrypt(release.Manifest)
	if err != nil {
		return nil, err
	}
	// todo: encrypt rel.Config[Raw]
	// release.Config.Raw, err = ChartValuesEncrypt(release.Config.Raw)
	// if err != nil {
	// 	return nil, err
	// }
	release.Hooks, err = HooksEncrypt(release.Hooks)
	if err != nil {
		return nil, err
	}
	return release, nil
}

// Release Decrypt
func ReleaseDecrypt(release *release.Release) (*release.Release, error) {
	var err error
	release.Chart, err = ChartDecrypt(release.Chart)
	if err != nil {
		return nil, err
	}
	release.Manifest, err = ChartValuesDecrypt(release.Manifest)
	if err != nil {
		return nil, err
	}
	// todo: decrypt rel.Config[Raw]
	// release.Config.Raw, err = ChartValuesDecrypt(release.Config.Raw)
	// if err != nil {
	// 	return nil, err
	// }
	release.Hooks, err = HooksDecrypt(release.Hooks)
	if err != nil {
		return nil, err
	}
	return release, nil
}

// encodeRelease encodes a byte returning a gzipped binary.
func encodeRelease(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(data); err != nil {
		return nil, err
	}
	w.Close()

	return buf.Bytes(), nil
}

// decodeRelease decodes the bytes in data.
func decodeRelease(data []byte) ([]byte, error) {
	// For backwards compatibility with releases that were stored before
	// compression was introduced we skip decompression if the
	// gzip magic header is not found
	if bytes.Equal(data[0:3], magicGzip) {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		b2, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
		data = b2
	}

	return data, nil
}
