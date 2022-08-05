package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	attest "github.com/takimoto3/app-attest"
	middleware "github.com/takimoto3/app-attest-middleware"
	"github.com/takimoto3/app-attest-middleware/handler"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/memcache"
)

type ChallengeType int

const (
	ForAttestation ChallengeType = iota
	ForAssertion
)

type AppUniquePubkey struct {
	UserID   string
	CreateAt time.Time
}

type Attestation struct {
	Environment      attest.Environment
	Couner           int64
	PublicKey        []byte
	PublicKeyBitSize int
	Receipt          []byte
}

type paramsKey struct{}

var Paramskey = paramsKey{}

var _ middleware.AssertionPlugin = (*SampleAssertionPlugin)(nil)

type SampleAssertionPlugin struct {
	verifiedData Attestation
}

func (plugin *SampleAssertionPlugin) getParams(r *http.Request) map[string]string {
	params, _ := r.Context().Value(Paramskey).(map[string]string)
	return params
}

func (plugin *SampleAssertionPlugin) ParseRequest(r *http.Request, requestBody []byte) (*http.Request, *attest.AssertionObject, string, error) {
	if len(requestBody) == 0 {
		return r, nil, "", nil
	}
	var params map[string]string
	if err := json.Unmarshal(requestBody, &params); err != nil {
		return r, nil, "", err
	}
	r = r.WithContext(context.WithValue(r.Context(), Paramskey, params))

	challenge := params["challenge"]
	authorization := r.Header.Get("Authorization")
	if authorization != "" {
		data, err := base64.RawURLEncoding.DecodeString(authorization[len("AppAssertion "):])
		if err != nil {
			return r, nil, "", err
		}
		assertionObj := attest.AssertionObject{}
		if err := assertionObj.Unmarshal(data); err != nil {
			return r, nil, "", err
		}
		return r, &assertionObj, challenge, nil
	}
	return r, nil, challenge, nil

}

func (plugin *SampleAssertionPlugin) GetAssignedChallenge(r *http.Request) (string, error) {
	challenge := plugin.getParams(r)["challenge"]
	ctx := r.Context()
	_, err := memcache.Get(ctx, challenge)
	if err != nil {
		if err == memcache.ErrCacheMiss {
			return "", nil
		}
		return "", err
	}
	memcache.Delete(ctx, challenge)

	return challenge, nil
}

func (p *SampleAssertionPlugin) ResponseNewChallenge(w http.ResponseWriter, r *http.Request) error {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return err
	}
	challenge := base64.RawURLEncoding.EncodeToString(buf)

	tms := make([]byte, binary.MaxVarintLen64)
	len := binary.PutVarint(buf, time.Now().Unix())
	if err := memcache.Add(r.Context(), &memcache.Item{Key: challenge, Value: tms[:len], Expiration: 3 * time.Second}); err != nil {
		return err
	}

	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Add("WWW-Authenticate", "AppAssertion-Challenge "+challenge)
	return nil
}

func (plugin *SampleAssertionPlugin) RedirectToAttestation(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/attest", http.StatusSeeOther)
}

func (plugin *SampleAssertionPlugin) GetPublicKeyAndCounter(r *http.Request) (*ecdsa.PublicKey, uint32, error) {
	userid := plugin.getParams(r)["userid"]
	if err := datastore.Get(r.Context(), datastore.NewKey(r.Context(), "Attestation", userid, 0, nil), &plugin.verifiedData); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	var curve elliptic.Curve
	switch plugin.verifiedData.PublicKeyBitSize {
	case elliptic.P224().Params().BitSize:
		curve = elliptic.P224()
	case elliptic.P256().Params().BitSize:
		curve = elliptic.P256()
	case elliptic.P384().Params().BitSize:
		curve = elliptic.P384()
	case elliptic.P521().Params().BitSize:
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}
	x, y := elliptic.Unmarshal(curve, plugin.verifiedData.PublicKey)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, uint32(plugin.verifiedData.Couner), nil
}

func (plugin *SampleAssertionPlugin) StoreNewCounter(r *http.Request, counter uint32) error {
	plugin.verifiedData.Couner = int64(counter)
	userid := plugin.getParams(r)["userid"]
	_, err := datastore.Put(r.Context(), datastore.NewKey(r.Context(), "Attestation", userid, 0, nil), &plugin.verifiedData)
	return err
}

var _ handler.AttestationPlugin = (*SampleAttestationPlugin)(nil)

type SampleAttestationPlugin struct{}

func (plugin *SampleAttestationPlugin) getParams(r *http.Request) map[string]string {
	params, _ := r.Context().Value(Paramskey).(map[string]string)
	return params
}
func (plugin *SampleAttestationPlugin) ParseRequest(r *http.Request) (*http.Request, *attest.AttestationObject, []byte, []byte, error) {
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return r, nil, nil, nil, err
	}
	var params map[string]string
	if err := json.Unmarshal(requestBody, &params); err != nil {
		return r, nil, nil, nil, err
	}
	r = r.WithContext(context.WithValue(r.Context(), Paramskey, params))

	data, err := base64.RawURLEncoding.DecodeString(params["attestation"])
	if err != nil {
		return r, nil, nil, nil, err
	}
	attestObj := attest.AttestationObject{}
	if err := attestObj.Unmarshal(data); err != nil {
		return r, nil, nil, nil, err
	}

	challengeData, err := base64.RawURLEncoding.DecodeString(params["challenge"])
	if err != nil {
		return r, nil, nil, nil, err
	}
	clientDataHash := sha256.Sum256(challengeData)

	keyId, err := base64.StdEncoding.DecodeString(params["keyId"])
	if err != nil {
		return r, nil, nil, nil, err
	}

	return r, &attestObj, clientDataHash[:], keyId, nil
}

func (plugin *SampleAttestationPlugin) GetAssignedChallenge(r *http.Request) (string, error) {
	challenge := plugin.getParams(r)["challenge"]
	ctx := r.Context()
	_, err := memcache.Get(ctx, challenge)
	if err != nil {
		if err == memcache.ErrCacheMiss {
			return "", nil
		}
		return "", err
	}
	memcache.Delete(ctx, challenge)

	return challenge, nil
}

func (plugin *SampleAttestationPlugin) ResponseNewChallenge(w http.ResponseWriter, r *http.Request) error {
	buf := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return err
	}
	challenge := base64.RawURLEncoding.EncodeToString(buf)

	tms := make([]byte, binary.MaxVarintLen64)
	len := binary.PutVarint(buf, time.Now().Unix())
	if err := memcache.Add(r.Context(), &memcache.Item{Key: challenge, Value: tms[:len], Expiration: 10 * time.Second}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Add("WWW-Authenticate", "AppAttest-Challenge "+challenge)
	return nil

}

func (plugin *SampleAttestationPlugin) StoreResult(r *http.Request, result *attest.Result) error {
	pubkeyData := elliptic.Marshal(result.PublicKey.Curve, result.PublicKey.X, result.PublicKey.Y)

	data := Attestation{
		Environment:      result.Environment,
		PublicKey:        pubkeyData,
		PublicKeyBitSize: result.PublicKey.Params().BitSize,
		Receipt:          result.Receipt,
	}
	pk := sha256.Sum256(pubkeyData)

	userid := plugin.getParams(r)["userid"]
	uniq := AppUniquePubkey{UserID: userid, CreateAt: time.Now()}
	return datastore.RunInTransaction(r.Context(), func(c context.Context) error {
		var exist AppUniquePubkey
		key := datastore.NewKey(c, "AppUniquePubkey", base64.RawStdEncoding.EncodeToString(pk[:]), 0, nil)
		if err := datastore.Get(c, key, &exist); err == nil {
			return errors.New("public key already exist.")
		} else {
			if err != datastore.ErrNoSuchEntity {
				return err
			}
			_, err = datastore.Put(c, key, &uniq)
			if err != nil {
				return err
			}
		}
		if _, err := datastore.Put(c, datastore.NewKey(c, "Attestation", userid, 0, nil), &data); err != nil {
			return err
		}
		return nil
	}, &datastore.TransactionOptions{XG: true})
}
