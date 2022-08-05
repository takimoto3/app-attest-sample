package main

import (
	"net/http"

	"github.com/nbio/hitch"
	attest "github.com/takimoto3/app-attest"
	middleware "github.com/takimoto3/app-attest-middleware"
	"github.com/takimoto3/app-attest-middleware/handler"
	"google.golang.org/appengine"
)

var appID = "<Your Team ID>.<Bundle ID>"

func main() {
	ah := handler.AttestationHandler{
		Logger: &AppEngineLogger{},
		AttestationService: &attest.AttestationService{
			AppID:         appID,
			PathForRootCA: "certs/Apple_App_Attestation_Root_CA.pem",
		},
		AttestationPlugin: &SampleAttestationPlugin{},
	}

	r := hitch.New()
	r.Get("/attest", http.HandlerFunc(ah.NewChallenge))
	r.Post("/attest", http.HandlerFunc(ah.VerifyAttestation))
	r.Post("/game/", http.HandlerFunc(Index), middleware.AppAttestAssert(&AppEngineLogger{}, appID, &SampleAssertionPlugin{}))

	http.Handle("/", r.Router)
	appengine.Main()
}

func Index(w http.ResponseWriter, r *http.Request) {

}
