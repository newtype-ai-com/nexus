package main

import (
	"errors"
	"net/http"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus"
)

// registrationHandler is the serve command's actual registration wiring. Keeping
// it separate lets tests prove that strict mode does not register admission
// routes, without starting a database, mail client or listening server.
func registrationHandler(cfg nexusserver.Config, ec gate.EnrolmentConfig, service *nexus.Service, authCredentials gate.CredentialStore, mailer gate.QuotaMailer) (http.Handler, error) {
	enrolment, err := gate.NewEnrolmentHandler(ec)
	if err != nil {
		return nil, errors.New("nexus: invalid enrolment configuration")
	}
	device, err := gate.NewDeviceHandler(ec)
	if err != nil {
		return nil, errors.New("nexus: invalid device configuration")
	}
	registration := http.NewServeMux()
	// Owner features follow the configured owner (NEXUS_OWNER_EMAIL); an empty
	// owner registers none of them.
	if gate.ValidOwnerEmail(cfg.OwnerEmail) {
		if !cfg.OwnerOnly {
			users, err := gate.NewUserAdmissionHandler(ec, gate.NexusAuth{Store: authCredentials, Service: service}.Authenticate)
			if err != nil {
				return nil, errors.New("nexus: invalid user admission configuration")
			}
			registration.Handle("/v1/users/requests", users)
			registration.Handle("/users/approve", users)
		}
		quota, err := gate.NewQuotaHandler(gate.QuotaConfig{Service: service, Store: authCredentials, Authenticate: gate.NexusAuth{Store: authCredentials, Service: service}.Authenticate, Mailer: mailer, BaseURL: ec.BaseURL, OwnerOnly: cfg.OwnerOnly, OwnerEmail: cfg.OwnerEmail})
		if err != nil {
			return nil, errors.New("nexus: invalid quota configuration")
		}
		registration.Handle("/v1/quota", quota)
		registration.Handle("/v1/quota/", quota)
		registration.Handle("/quota/approve", quota)
	}
	registration.Handle("/v1/device", device)
	registration.Handle("/v1/device/", device)
	registration.Handle("/device/confirm", device)
	registration.Handle("/", enrolment)
	return registration, nil
}
